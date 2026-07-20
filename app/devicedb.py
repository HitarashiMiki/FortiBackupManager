from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .storage import RemoteStorage, StorageError

# Nagłówek pliku bazy. FBK1 = schemat 1 (tylko lista urządzeń). FBK2 = schemat 2
# (foldery + min_reader_version).
MAGIC_V1 = b"FBK1"
MAGIC = b"FBK2"
MAGIC_PREFIX = b"FBK"
SALT_LEN = 16
KDF_ITERATIONS = 480_000
DB_FILENAME = "devices.db"

# Najwyższa wersja schematu, którą TA wersja programu rozumie i może
# bezpiecznie zapisywać.
DB_SCHEMA_VERSION = 2

DB_TOO_NEW_MSG = (
    "Baza urządzeń została zapisana przez nowszą wersję programu "
    "(schemat {found}, ta wersja obsługuje maks. {supported}). "
    "Zaktualizuj FortiBackup Web — otwarcie starszą wersją mogłoby "
    "bezpowrotnie usunąć dane."
)


class DeviceDBError(Exception):
    pass


class WrongPasswordError(DeviceDBError):
    pass


class DBTooNewError(DeviceDBError):
    """Baza zapisana przez nowszą wersję programu — wymagany update aplikacji."""
    pass


@dataclass
class Device:
    name: str
    host: str
    port: int = 22
    username: str = "admin"
    password: str = ""
    method: str = "ssh_push"
    api_token: str = ""
    api_port: int = 443
    vdom_enabled: bool = False
    description: str = ""
    # Harmonogram automatycznych backupów
    sched_enabled: bool = False
    sched_mode: str = "daily"        # "interval" | "daily" | "weekly"
    sched_every_hours: int = 24      # dla trybu interval
    sched_time: str = "02:00"        # dla daily/weekly (HH:MM)
    sched_weekday: int = 0           # dla weekly (0 = poniedziałek)
    folder: str = ""
    # Nazwa katalogu z backupami na magazynie ("" = pochodna nazwy urządzenia,
    # jak dotychczas). Ustawiane, gdy backupy trzeba przypiąć do katalogu
    # o INNEJ nazwie: odtwarzanie bazy urządzeń (dopasowanie po hoście
    # z .fbk-meta.json) albo zmiana nazwy urządzenia (ciągłość historii).
    backup_dir: str = ""
    # Pola nieznane tej wersji programu (dopisane przez nowszą, kompatybilną
    # wersję) — przechowywane i oddawane przy zapisie, żeby edycja starszą
    # wersją nie wycinała cudzych danych.
    extra: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        extra = d.pop("extra") or {}
        # znane pola mają pierwszeństwo przed przechowanymi nieznanymi
        return {**extra, **d}

    @staticmethod
    def from_dict(d: dict) -> "Device":
        known = {f for f in Device.__dataclass_fields__ if f != "extra"}
        kwargs = {k: v for k, v in d.items() if k in known}
        kwargs["extra"] = {k: v for k, v in d.items() if k not in known}
        return Device(**kwargs)


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_db(devices: List[Device], password: str, salt: Optional[bytes] = None,
               folders: Optional[List[str]] = None,
               extra: Optional[dict] = None) -> bytes:
    salt = salt or os.urandom(SALT_LEN)
    key = _derive_key(password, salt)
    data = dict(extra or {}) 
    data.update({
        "version": DB_SCHEMA_VERSION,
        # Minimalna wersja schematu, jaką musi rozumieć program, żeby móc
        # bezpiecznie CZYTAĆ I ZAPISYWAĆ tę bazę.
        "min_reader_version": 2,
        "devices": [d.to_dict() for d in devices],
        "folders": sorted(set(folders or []), key=str.lower),
    })
    payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
    token = Fernet(key).encrypt(payload)
    return MAGIC + salt + token


def decrypt_payload(blob: bytes, password: str) -> dict:
    """Odszyfrowuje bazę (FBK1 lub FBK2) i zwraca surowy payload JSON.
    Rzuca DBTooNewError, gdy bazę zapisała nowsza wersja programu."""
    if len(blob) < len(MAGIC) + SALT_LEN or not blob.startswith(MAGIC_PREFIX):
        raise DeviceDBError("Nieprawidłowy format pliku bazy urządzeń.")
    magic = blob[:len(MAGIC)]
    if magic not in (MAGIC_V1, MAGIC):
        # FBK3+ — nagłówek z przyszłości, nawet nie próbujemy deszyfrować
        raise DBTooNewError(DB_TOO_NEW_MSG.format(
            found=magic.decode("ascii", errors="replace"),
            supported=DB_SCHEMA_VERSION))
    salt = blob[len(MAGIC):len(MAGIC) + SALT_LEN]
    token = blob[len(MAGIC) + SALT_LEN:]
    key = _derive_key(password, salt)
    try:
        payload = Fernet(key).decrypt(token)
    except InvalidToken:
        raise WrongPasswordError("Błędne hasło lub uszkodzona baza.")
    data = json.loads(payload.decode("utf-8"))
    min_reader = int(data.get("min_reader_version", 1))
    if min_reader > DB_SCHEMA_VERSION:
        raise DBTooNewError(DB_TOO_NEW_MSG.format(
            found=min_reader, supported=DB_SCHEMA_VERSION))
    return data


def decrypt_db(blob: bytes, password: str) -> Tuple[List[Device], List[str]]:
    data = decrypt_payload(blob, password)
    devices = [Device.from_dict(d) for d in data.get("devices", [])]
    # foldery = zadeklarowane + te faktycznie użyte na urządzeniach
    folders = set(data.get("folders", []))
    folders.update(d.folder for d in devices if d.folder)
    return devices, sorted(folders, key=str.lower)


class DeviceDB:
    def __init__(self, storage: RemoteStorage, password: str):
        self.storage = storage
        self.password = password
        self.devices: List[Device] = []
        self.folders: List[str] = []
        self._extra: dict = {}
        self._salt: Optional[bytes] = None

    @property
    def remote_path(self) -> str:
        return self.storage.join(DB_FILENAME)

    def _ingest(self, blob: bytes) -> None:
        data = decrypt_payload(blob, self.password)
        self.devices = [Device.from_dict(d) for d in data.get("devices", [])]
        folders = set(data.get("folders", []))
        folders.update(d.folder for d in self.devices if d.folder)
        self.folders = sorted(folders, key=str.lower)
        self._extra = {k: v for k, v in data.items()
                       if k not in ("version", "min_reader_version",
                                    "devices", "folders")}

    def load_or_create(self) -> bool:
        self.storage.ensure_dir(self.storage.cfg.base_path)
        if self.storage.exists(self.remote_path):
            blob = self.storage.download_bytes(self.remote_path)
            self._ingest(blob)
            self._salt = blob[len(MAGIC):len(MAGIC) + SALT_LEN]
            return True
        self.devices = []
        self.folders = []
        self.save()
        return False

    def save(self) -> None:
        blob = encrypt_db(self.devices, self.password, self._salt,
                          folders=self.folders, extra=self._extra)
        if self._salt is None:
            self._salt = blob[len(MAGIC):len(MAGIC) + SALT_LEN]
        self.storage.upload_bytes(blob, self.remote_path)

    def reload(self) -> None:
        if self.storage.exists(self.remote_path):
            blob = self.storage.download_bytes(self.remote_path)
            self._ingest(blob)

    def get(self, name: str) -> Optional[Device]:
        return next((d for d in self.devices if d.name == name), None)

    def upsert(self, device: Device, old_name: Optional[str] = None) -> None:
        try:
            self.reload()
        except StorageError:
            pass
        key = old_name or device.name
        for i, d in enumerate(self.devices):
            if d.name == key:
                self.devices[i] = device
                break
        else:
            if self.get(device.name):
                raise DeviceDBError(f"Urządzenie o nazwie '{device.name}' już istnieje.")
            self.devices.append(device)
        self.devices.sort(key=lambda d: d.name.lower())
        self.save()

    def remove(self, name: str) -> None:
        try:
            self.reload()
        except StorageError:
            pass
        self.devices = [d for d in self.devices if d.name != name]
        self.save()

    # -- foldery ---------------------------------------------------------------

    def add_folder(self, name: str) -> None:
        try:
            self.reload()
        except StorageError:
            pass
        name = name.strip()
        if not name:
            raise DeviceDBError("Nazwa folderu nie może być pusta.")
        if any(f.lower() == name.lower() for f in self.folders):
            raise DeviceDBError(f"Folder '{name}' już istnieje.")
        self.folders.append(name)
        self.folders.sort(key=str.lower)
        self.save()

    def remove_folder(self, name: str) -> int:
        """Usuwa folder; Urządzenia są przenoszone poza folder"""
        try:
            self.reload()
        except StorageError:
            pass
        if name not in self.folders:
            raise DeviceDBError(f"Folder '{name}' nie istnieje.")
        moved = 0
        for d in self.devices:
            if d.folder == name:
                d.folder = ""
                moved += 1
        self.folders = [f for f in self.folders if f != name]
        self.save()
        return moved

    def move_device(self, name: str, folder: str) -> None:
        try:
            self.reload()
        except StorageError:
            pass
        device = self.get(name)
        if not device:
            raise DeviceDBError(f"Urządzenie '{name}' nie istnieje.")
        folder = folder.strip()
        if folder and folder not in self.folders:
            raise DeviceDBError(f"Folder '{folder}' nie istnieje.")
        device.folder = folder
        self.save()