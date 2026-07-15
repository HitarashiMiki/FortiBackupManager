from __future__ import annotations

import posixpath
import re
import socket
import time
from datetime import datetime
from typing import Callable, Optional

from .devicedb import Device
from .storage import RemoteStorage, StorageConfig

BACKUP_DIR = "backups"
TS_FORMAT = "%Y%m%d_%H%M%S"

Logger = Callable[[str], None]


class FortiGateError(Exception):
    pass


def _log(logger: Optional[Logger], msg: str) -> None:
    if logger:
        logger(msg)


def sanitize_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "device"


def build_backup_filename(device: Device, when: Optional[datetime] = None) -> str:
    when = when or datetime.now()
    return f"{sanitize_name(device.name)}_{when.strftime(TS_FORMAT)}.conf"


def device_backup_dir(storage: RemoteStorage, device: Device) -> str:
    return storage.join(BACKUP_DIR, sanitize_name(device.name))


# ======================== SSH PUSH ========================

class _FortiShell:
    def __init__(self, device: Device, logger: Optional[Logger] = None):
        self.device = device
        self.logger = logger
        self.client = None
        self.chan = None

    def open(self) -> None:
        import paramiko
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.client.connect(
                self.device.host,
                port=self.device.port,
                username=self.device.username,
                password=self.device.password,
                look_for_keys=False,
                allow_agent=False,
                timeout=15,
                banner_timeout=15,
                auth_timeout=15,
            )
        except (paramiko.SSHException, socket.error, OSError) as e:
            raise FortiGateError(f"SSH: nie można połączyć się z {self.device.host}: {e}") from e
        self.chan = self.client.invoke_shell(width=200)
        self.chan.settimeout(0.0)
        self._read_until_prompt(timeout=30)

    def close(self) -> None:
        try:
            if self.chan:
                self.chan.close()
            if self.client:
                self.client.close()
        finally:
            self.chan = None
            self.client = None

    @staticmethod
    def _looks_like_prompt(buf: str) -> bool:
        tail = buf.rstrip()
        if not tail:
            return False
        last = tail.splitlines()[-1].strip()
        return last.endswith("#") or last.endswith("$")

    def _read_until_prompt(self, timeout: float = 60) -> str:
        buf = ""
        deadline = time.time() + timeout
        last_activity = time.time()
        nudged = False
        while time.time() < deadline:
            if self.chan.recv_ready():
                chunk = self.chan.recv(65536).decode("utf-8", errors="replace")
                buf += chunk
                last_activity = time.time()
                low_tail = buf[-300:].lower()
                if "'a' to accept" in low_tail or "(press 'a'" in low_tail:
                    self.chan.send("a")
                    buf = ""
                    continue
                if "--more--" in low_tail:
                    self.chan.send(" ")
                    buf = buf.replace("--More--", "").replace("--more--", "")
                    continue
                if self._looks_like_prompt(buf):
                    return buf
            else:
                if not nudged and time.time() - last_activity > 3:
                    self.chan.send("\n")
                    nudged = True
                    last_activity = time.time()
                time.sleep(0.1)
        tail = "\n".join(buf.strip().splitlines()[-5:]) if buf.strip() else "(brak danych)"
        raise FortiGateError(f"SSH timeout.\nOstatnie dane:\n{tail}")

    def cmd(self, command: str, timeout: float = 60) -> str:
        _log(self.logger, f"  > {command.split()[0]} ...")
        self.chan.send(command + "\n")
        out = self._read_until_prompt(timeout=timeout)
        return out


def backup_ssh_push(device: Device, storage: RemoteStorage, logger: Optional[Logger] = None) -> str:
    cfg: StorageConfig = storage.cfg
    if cfg.protocol not in ("ftp", "ftps", "sftp"):
        raise FortiGateError("Metoda ssh_push wymaga magazynu FTP lub SFTP.")

    filename = build_backup_filename(device)
    remote_dir = device_backup_dir(storage, device)
    remote_path = posixpath.join(remote_dir, filename)

    storage.ensure_dir(remote_dir)

    proto = "sftp" if cfg.protocol == "sftp" else "ftp"
    server = cfg.host if _default_port(proto, cfg.port) else f"{cfg.host}:{cfg.port}"
    command = f'execute backup config {proto} "{remote_path}" {server} "{cfg.username}" "{cfg.password}"'

    shell = _FortiShell(device, logger)
    try:
        shell.open()
        _log(logger, f"[{device.name}] Połączono po SSH.")
        if device.vdom_enabled:
            shell.cmd("config global", timeout=15)
        out = shell.cmd(command, timeout=180)
        low = out.lower()
        if "fail" in low or "error" in low or "invalid" in low:
            raise FortiGateError(f"FortiGate zgłosił błąd:\n{out[-500:]}")
        _log(logger, f"[{device.name}] Urządzenie potwierdziło backup.")
    finally:
        shell.close()

    for _ in range(10):
        if storage.exists(remote_path):
            _log(logger, f"[{device.name}] Zweryfikowano plik: {remote_path}")
            return remote_path
        time.sleep(1)
    raise FortiGateError("Plik nie pojawił się na magazynie.")


def _default_port(proto: str, port: int) -> bool:
    return (proto == "ftp" and port == 21) or (proto == "sftp" and port == 22)


# ======================== API PULL ========================

def backup_api_pull(device: Device, storage: RemoteStorage, logger: Optional[Logger] = None, verify_tls: bool = False) -> str:
    import requests
    import urllib3

    if not device.api_token:
        raise FortiGateError("Metoda api_pull wymaga tokenu API.")

    if not verify_tls:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    url = f"https://{device.host}:{device.api_port}/api/v2/monitor/system/config/backup"
    params = {"scope": "global"}
    headers = {"Authorization": f"Bearer {device.api_token}"}

    def _call(method: str):
        try:
            return requests.request(method, url, params=params, headers=headers, verify=verify_tls, timeout=(15, 60))
        except requests.RequestException as e:
            raise FortiGateError(f"błąd połączenia API: {e}") from e

    _log(logger, f"[{device.name}] Pobieram przez REST API (POST)...")
    r = _call("POST")
    if r.status_code == 405:
        _log(logger, f"[{device.name}] POST niedozwolony — próbuję GET...")
        r = _call("GET")

    if r.status_code == 401:
        raise FortiGateError("API: 401 — sprawdź token i trusted hosts.")
    if r.status_code == 403:
        raise FortiGateError("API: 403 — brak uprawnień.")
    if r.status_code != 200:
        raise FortiGateError(f"API: nieoczekiwany kod {r.status_code}.")

    data = r.content
    if not data.lstrip().startswith(b"#config-version"):
        raise FortiGateError("API: odpowiedź nie wygląda na konfigurację FortiGate.")

    filename = build_backup_filename(device)
    remote_path = posixpath.join(device_backup_dir(storage, device), filename)
    storage.upload_bytes(data, remote_path)
    _log(logger, f"[{device.name}] Zapisano {len(data)} B")
    return remote_path


def run_backup(device: Device, storage: RemoteStorage, logger: Optional[Logger] = None) -> str:
    if device.method == "api_pull":
        return backup_api_pull(device, storage, logger)
    return backup_ssh_push(device, storage, logger)