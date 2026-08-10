from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
from collections import OrderedDict
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

# Paleta kolorów folderów (do priorytetyzacji/organizacji). Pusty kolor =
# domyślny (bursztyn w UI). Walidacja server-side ogranicza wartości do tej
# listy — nie chcemy dowolnego stringa lądującego w atrybucie stylu.
FOLDER_COLORS = ("#8b949e", "#f85149", "#db6d28", "#d29922",
                 "#3fb950", "#1f6feb", "#a371f7", "#db61a2", "#39c5cf")


def normalize_folder_color(color: str) -> str:
    """Zwraca kolor z palety (małe litery) albo "" dla pustego/nieznanego."""
    color = (color or "").strip().lower()
    return color if color in FOLDER_COLORS else ""


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
    # Retencja starych kopii (per urządzenie). Automatyczne usuwanie nadmiaru
    # po każdym udanym backupie — patrz retention.py.
    retention_mode: str = "off"      # "off" | "count" | "days" | "gfs"
    retention_count: int = 30        # dla "count": ile ostatnich kopii trzymać
    retention_days: int = 90         # dla "days": usuń starsze niż N dni
    gfs_daily: int = 7               # GFS: ile ostatnich dni (1 kopia/dzień)
    gfs_weekly: int = 4              # GFS: ile ostatnich tygodni (1 kopia/tydz.)
    gfs_monthly: int = 12            # GFS: ile ostatnich miesięcy (1 kopia/mies.)
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


_KEY_CACHE: "OrderedDict[bytes, bytes]" = OrderedDict()
_KEY_CACHE_LOCK = threading.Lock()
KEY_CACHE_MAX = 16          # w praktyce 1-2 wpisy (jedno hasło, jedna sól)


def _derive_key(password: str, salt: bytes) -> bytes:
    ck = hashlib.sha256(b"fbk-kdf\0" + salt + password.encode("utf-8")).digest()
    with _KEY_CACHE_LOCK:
        key = _KEY_CACHE.get(ck)
        if key is not None:
            _KEY_CACHE.move_to_end(ck)
            return key
    # Poza lockiem: dwa wątki mogą policzyć to samo równolegle (nieszkodliwe),
    # ale nikt nie czeka pod lockiem przez 100 ms.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    with _KEY_CACHE_LOCK:
        _KEY_CACHE[ck] = key
        _KEY_CACHE.move_to_end(ck)
        while len(_KEY_CACHE) > KEY_CACHE_MAX:
            _KEY_CACHE.popitem(last=False)
    return key


def clear_key_cache() -> None:
    """Czyści cache kluczy (wylogowanie wszystkich / testy)."""
    with _KEY_CACHE_LOCK:
        _KEY_CACHE.clear()



DB_LOCK = threading.RLock()

# Licznik zapisów bazy. UI odpytuje go przez /api/state, żeby wiedzieć, że
# KTOŚ INNY zmienił inwentarz i trzeba przeładować listę urządzeń.
_REVISION = 0
_REVISION_LOCK = threading.Lock()


def db_revision() -> int:
    with _REVISION_LOCK:
        return _REVISION


def _bump_revision() -> None:
    global _REVISION
    with _REVISION_LOCK:
        _REVISION += 1


def encrypt_db(devices: List[Device], password: str, salt: Optional[bytes] = None,
               folders: Optional[List[str]] = None,
               folder_colors: Optional[dict] = None,
               extra: Optional[dict] = None) -> bytes:
    salt = salt or os.urandom(SALT_LEN)
    key = _derive_key(password, salt)
    data = dict(extra or {})
    data.update({
        "version": DB_SCHEMA_VERSION,
        # Minimalna wersja schematu, jaką musi rozumieć program, żeby móc
        # bezpiecznie CZYTAĆ I ZAPISYWAĆ tę bazę. Kolory folderów to dodatek
        # czysto kosmetyczny — stary klient FBK2 przechowa je przez `extra`,
        # więc NIE podbijamy min_reader_version.
        "min_reader_version": 2,
        "devices": [d.to_dict() for d in devices],
        "folders": sorted(set(folders or []), key=str.lower),
        "folder_colors": dict(folder_colors or {}),
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
        self.folder_colors: Dict[str, str] = {}   # nazwa folderu -> hex koloru
        self._extra: dict = {}
        self._salt: Optional[bytes] = None

    @property
    def db_path(self) -> str:
        return self.storage.join(DB_FILENAME)

    def _ingest(self, blob: bytes) -> None:
        data = decrypt_payload(blob, self.password)
        self.devices = [Device.from_dict(d) for d in data.get("devices", [])]
        folders = set(data.get("folders", []))
        folders.update(d.folder for d in self.devices if d.folder)
        self.folders = sorted(folders, key=str.lower)
        colors = data.get("folder_colors") or {}
        # tylko kolory istniejących folderów (porządki po skasowanych)
        self.folder_colors = {f: c for f, c in colors.items() if f in folders}
        self._extra = {k: v for k, v in data.items()
                       if k not in ("version", "min_reader_version",
                                    "devices", "folders", "folder_colors")}

    def load_or_create(self) -> bool:
        # Odczyt też pod DB_LOCK: inaczej można trafić na moment podmiany pliku
        # przez cudzy zapis i zobaczyć stan "w połowie" (albo — na Windows —
        # zablokować tę podmianę otwartym uchwytem).
        with DB_LOCK:
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
        with DB_LOCK:
            blob = encrypt_db(self.devices, self.password, self._salt,
                              folders=self.folders, folder_colors=self.folder_colors,
                              extra=self._extra)
            if self._salt is None:
                self._salt = blob[len(MAGIC):len(MAGIC) + SALT_LEN]
            self.storage.upload_bytes(blob, self.remote_path)
            _bump_revision()

    def reload(self) -> None:
        with DB_LOCK:
            if self.storage.exists(self.remote_path):
                blob = self.storage.download_bytes(self.remote_path)
                self._ingest(blob)

    def get(self, name: str) -> Optional[Device]:
        return next((d for d in self.devices if d.name == name), None)

    def upsert(self, device: Device, old_name: Optional[str] = None) -> None:
        with DB_LOCK:
            try:
                self.reload()
            except StorageError:
                pass
            key = old_name or device.name
            # Zmiana nazwy nie tworzy dwóch urządzeń o tej samej nazwie. Nazwa jest unikalnym kluczem.
            if device.name != key and any(d.name == device.name for d in self.devices):
                raise DeviceDBError(f"Urządzenie o nazwie '{device.name}' już istnieje.")
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
        with DB_LOCK:
            try:
                self.reload()
            except StorageError:
                pass
            self.devices = [d for d in self.devices if d.name != name]
            self.save()

    # -- foldery ---------------------------------------------------------------

    def add_folder(self, name: str, color: str = "") -> None:
        with DB_LOCK:
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
            color = normalize_folder_color(color)
            if color:
                self.folder_colors[name] = color
            self.save()

    def set_folder_color(self, name: str, color: str) -> None:
        with DB_LOCK:
            try:
                self.reload()
            except StorageError:
                pass
            if name not in self.folders:
                raise DeviceDBError(f"Folder '{name}' nie istnieje.")
            color = normalize_folder_color(color)
            if color:
                self.folder_colors[name] = color
            else:
                self.folder_colors.pop(name, None)   # pusty = kolor domyślny
            self.save()

    def remove_folder(self, name: str) -> int:
        """Usuwa folder; Urządzenia są przenoszone poza folder"""
        with DB_LOCK:
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
            self.folder_colors.pop(name, None)
            self.save()
            return moved

    def move_device(self, name: str, folder: str) -> None:
        with DB_LOCK:
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

    def mutate(self, fn):
        """Wykonuje dowolną zmianę pod DB_LOCK na ŚWIEŻO wczytanej bazie.

        Dla endpointów, które nie mieszczą się w gotowych metodach wyżej
        (np. retencja: znajdź urządzenie → zmień pola → zapisz). `fn` dostaje
        `self` i musi sam wywołać `save()`. Bez tego endpoint budowałby zmianę
        na stanie sprzed cudzego zapisu."""
        with DB_LOCK:
            try:
                self.reload()
            except StorageError:
                pass
            return fn(self)