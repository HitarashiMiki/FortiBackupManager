from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, asdict
from typing import List, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .storage import RemoteStorage, StorageError

MAGIC = b"FBK1"
SALT_LEN = 16
KDF_ITERATIONS = 480_000
DB_FILENAME = "devices.db"


class DeviceDBError(Exception):
    pass


class WrongPasswordError(DeviceDBError):
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
    # Harmonogram automatycznych backupów (per urządzenie, współdzielony
    # przez zespół — żyje w zaszyfrowanej bazie na magazynie)
    sched_enabled: bool = False
    sched_mode: str = "daily"        # "interval" | "daily" | "weekly"
    sched_every_hours: int = 24      # dla trybu interval
    sched_time: str = "02:00"        # dla daily/weekly (HH:MM)
    sched_weekday: int = 0           # dla weekly (0 = poniedziałek)

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Device":
        known = {f for f in Device.__dataclass_fields__}
        return Device(**{k: v for k, v in d.items() if k in known})


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_db(devices: List[Device], password: str, salt: Optional[bytes] = None) -> bytes:
    salt = salt or os.urandom(SALT_LEN)
    key = _derive_key(password, salt)
    payload = json.dumps(
        {"version": 1, "devices": [d.to_dict() for d in devices]},
        ensure_ascii=False,
    ).encode("utf-8")
    token = Fernet(key).encrypt(payload)
    return MAGIC + salt + token


def decrypt_db(blob: bytes, password: str) -> List[Device]:
    if len(blob) < len(MAGIC) + SALT_LEN or not blob.startswith(MAGIC):
        raise DeviceDBError("Nieprawidłowy format pliku bazy urządzeń.")
    salt = blob[len(MAGIC):len(MAGIC) + SALT_LEN]
    token = blob[len(MAGIC) + SALT_LEN:]
    key = _derive_key(password, salt)
    try:
        payload = Fernet(key).decrypt(token)
    except InvalidToken:
        raise WrongPasswordError("Błędne hasło główne lub uszkodzona baza.")
    data = json.loads(payload.decode("utf-8"))
    return [Device.from_dict(d) for d in data.get("devices", [])]


class DeviceDB:
    def __init__(self, storage: RemoteStorage, password: str):
        self.storage = storage
        self.password = password
        self.devices: List[Device] = []
        self._salt: Optional[bytes] = None

    @property
    def remote_path(self) -> str:
        return self.storage.join(DB_FILENAME)

    def load_or_create(self) -> bool:
        self.storage.ensure_dir(self.storage.cfg.base_path)
        if self.storage.exists(self.remote_path):
            blob = self.storage.download_bytes(self.remote_path)
            self.devices = decrypt_db(blob, self.password)
            self._salt = blob[len(MAGIC):len(MAGIC) + SALT_LEN]
            return True
        self.devices = []
        self.save()
        return False

    def save(self) -> None:
        blob = encrypt_db(self.devices, self.password, self._salt)
        if self._salt is None:
            self._salt = blob[len(MAGIC):len(MAGIC) + SALT_LEN]
        self.storage.upload_bytes(blob, self.remote_path)

    def reload(self) -> None:
        if self.storage.exists(self.remote_path):
            blob = self.storage.download_bytes(self.remote_path)
            self.devices = decrypt_db(blob, self.password)

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