# -*- coding: utf-8 -*-
"""
changes.py — wykrywanie realnych zmian konfiguracji między backupami.

Po każdym backupie (manualnym i z harmonogramu) porównujemy ZNORMALIZOWANĄ
nową wersję z poprzednią (normalize_config maskuje pola ulotne FortiOS:
sekrety ENC, klucze prywatne, conf_file_ver — inaczej każdy backup
wyglądałby na zmieniony). Wynik ląduje w małym pliku meta obok backupów
urządzenia na magazynie — dzięki temu cały zespół widzi te same znaczniki
i nie trzeba niczego przeliczać przy listowaniu wersji.

Format .fbk-meta.json: {"changed": {"<nazwa_pliku>": true/false}}
Brak wpisu = nie wiadomo (stare backupy sprzed tej funkcji, pierwszy
backup urządzenia) — UI wtedy po prostu nie pokazuje kropki.
"""

from __future__ import annotations

import json
import posixpath
import re
from typing import Dict, Optional

from .diff import normalize_config
from .storage import RemoteStorage, StorageError

META_FILENAME = ".fbk-meta.json"


def _basename(path: str) -> str:
    """Nazwa pliku niezależnie od separatora.

    `posixpath.basename` na ścieżce z backslashami (LocalStorage na Windows)
    oddaje CAŁĄ ścieżkę — porównanie z nazwami plików wtedy nigdy nie trafia
    i detekcja zmian po cichu zwraca „nie wiadomo". Patrz pułapka 9.17."""
    return re.split(r"[\\/]", path)[-1]


def load_meta(storage: RemoteStorage, device_dir: str) -> dict:
    path = posixpath.join(device_dir, META_FILENAME)
    try:
        if storage.exists(path):
            return json.loads(storage.download_bytes(path).decode("utf-8"))
    except (StorageError, ValueError):
        pass 
    return {}


def _save_meta(storage: RemoteStorage, device_dir: str, meta: dict) -> None:
    path = posixpath.join(device_dir, META_FILENAME)
    storage.upload_bytes(json.dumps(meta, ensure_ascii=False).encode("utf-8"), path)


def changed_flags(storage: RemoteStorage, device_dir: str) -> Dict[str, bool]:
    """Mapa nazwa_pliku -> czy różni się od poprzedniej wersji."""
    meta = load_meta(storage, device_dir)
    flags = meta.get("changed", {})
    return flags if isinstance(flags, dict) else {}


def record_change_flag(storage: RemoteStorage, device_dir: str,
                       new_path: str) -> Optional[bool]:
    """Porównuje świeży backup z poprzednią wersją i zapisuje wynik w meta.

    Zwraca True/False (są zmiany / brak zmian) albo None, gdy nie ma
    z czym porównać."""
    new_name = _basename(new_path)
    prev_name = _previous_name(storage, device_dir, new_name)
    if prev_name is None:
        return None

    new_text = storage.download_bytes(new_path).decode("utf-8", errors="replace")
    prev_text = storage.download_bytes(
        posixpath.join(device_dir, prev_name)).decode("utf-8", errors="replace")
    changed = normalize_config(new_text) != normalize_config(prev_text)

    meta = load_meta(storage, device_dir)
    meta.setdefault("changed", {})[new_name] = changed
    _save_meta(storage, device_dir, meta)
    return changed


def record_device_identity(storage: RemoteStorage, device_dir: str,
                           device) -> None:
    """Zapisuje w meta katalogu tożsamość urządzenia (nazwa + host).
    Dzięki temu po utracie bazy urządzeń da się dopasować katalogi backupów
    do ponownie dodanych urządzeń po ADRESIE, nie tylko po nazwie."""
    meta = load_meta(storage, device_dir)
    ident = {"name": device.name, "host": device.host}
    if meta.get("device") != ident:
        meta["device"] = ident
        _save_meta(storage, device_dir, meta)


def find_backup_dir_for_host(storage: RemoteStorage, backups_root: str,
                             host: str, claimed) -> Optional[str]:
    """Szuka osieroconego katalogu backupów (spoza `claimed`), którego meta
    wskazuje ten sam host. Przy wielu kandydatach (np. stare katalogi po
    zmianach nazwy) wygrywa ten z najświeższym backupiem."""
    candidates = []
    for d in storage.list_dirs(backups_root):
        if d in claimed:
            continue
        meta = load_meta(storage, posixpath.join(backups_root, d))
        if (meta.get("device") or {}).get("host") != host:
            continue
        files = [f.name for f in storage.list_files(posixpath.join(backups_root, d))
                 if not f.name.startswith(".")]
        if files:
            # nazwy niosą timestamp — max = najnowszy backup
            candidates.append((max(files), d))
    if not candidates:
        return None
    return max(candidates)[1]


def detect_and_log(storage: RemoteStorage, device_dir: str, new_path: str,
                   log, device=None) -> Optional[bool]:
    """Wrapper dla jobów backupu: porównaj, zaloguj,
    nieudana detekcja zmian nie może unieważnić udanego backupu.
    Przy okazji odświeża tożsamość urządzenia w meta (patrz wyżej).

    Zwraca True/False/None (zmienione / bez zmian / nie wiadomo) — harmonogram
    używa tego do zwijania identycznych kopii (patrz collapse_unchanged)."""
    if device is not None:
        try:
            record_device_identity(storage, device_dir, device)
        except Exception as e:  # noqa: BLE001
            log(f"Nie udało się zapisać metadanych urządzenia: {e}")
    try:
        changed = record_change_flag(storage, device_dir, new_path)
    except Exception as e:  # noqa: BLE001
        log(f"Nie udało się porównać z poprzednią wersją: {e}")
        return None
    if changed is True:
        log("Wykryto zmiany konfiguracji względem poprzedniej wersji")
    elif changed is False:
        log("Brak zmian względem poprzedniej wersji")
    return changed


def _previous_name(storage: RemoteStorage, device_dir: str, new_name: str) -> Optional[str]:
    """Nazwa kopii bezpośrednio poprzedzającej `new_name` (nazwy niosą
    timestamp, więc porównanie leksykalne = porównanie chronologiczne)."""
    candidates = [f.name for f in storage.list_files(device_dir)
                  if f.name != new_name and not f.name.startswith(".")]
    return max((n for n in candidates if n < new_name), default=None)


def collapse_unchanged(storage: RemoteStorage, device_dir: str, new_path: str,
                       log) -> str:
    """Nowa kopia jest identyczna z poprzednią — zamiast trzymać dwa takie same
    pliki, kasujemy nową, a POPRZEDNIĄ przemianowujemy na nową nazwę.

    Po co: urządzenie, którego konfiguracji nikt nie rusza, produkowało
    codziennie identyczny plik. Po zwinięciu zostaje jedna kopia z aktualną
    datą — czyli "sprawdzone dziś, treść ta sama".

    Data pierwszego wystąpienia tej treści NIE ginie: ląduje w meta pod
    `first_seen`, więc widać, od kiedy konfiguracja się nie zmieniła.

    Zwraca ścieżkę kopii, która obowiązuje po operacji (przy jakimkolwiek
    problemie — nietkniętą nową, bo lepiej mieć kopię za dużo niż za mało).
    """
    new_name = _basename(new_path)
    prev_name = _previous_name(storage, device_dir, new_name)
    if prev_name is None:
        return new_path
    prev_path = posixpath.join(device_dir, prev_name)

    meta = load_meta(storage, device_dir)
    changed = meta.get("changed", {})
    first_seen = meta.get("first_seen", {})
    # od kiedy ta treść jest niezmieniona: jeśli poprzednia kopia sama była
    # już zwinięta, przenosimy jej znacznik dalej
    origin = first_seen.get(prev_name) or prev_name

    try:
        storage.delete(new_path)
        storage.rename(prev_path, new_path)
    except StorageError as e:
        log(f"Nie udało się zwinąć identycznej kopii: {e}")
        return new_path

    # Flaga „czy różni się od poprzedniej" należy do TREŚCI, nie do nazwy —
    # przenosimy ją razem z plikiem, żeby kropka w UI dalej mówiła prawdę.
    if prev_name in changed:
        changed[new_name] = changed.pop(prev_name)
    else:
        changed.pop(new_name, None)
    first_seen.pop(prev_name, None)
    first_seen[new_name] = origin
    meta["changed"] = changed
    meta["first_seen"] = first_seen
    _save_meta(storage, device_dir, meta)

    log(f"Konfiguracja bez zmian — zachowano jedną kopię (bez zmian od {_stamp(origin)})")
    return new_path


def first_seen_map(storage: RemoteStorage, device_dir: str) -> Dict[str, str]:
    """Mapa nazwa_pliku -> nazwa pierwszej kopii z tą samą treścią."""
    meta = load_meta(storage, device_dir)
    seen = meta.get("first_seen", {})
    return seen if isinstance(seen, dict) else {}


def _stamp(filename: str) -> str:
    """Data z nazwy pliku backupu w czytelnej formie (do komunikatów)."""
    m = re.search(r"_(\d{8})_(\d{6})\.conf$", filename)
    if not m:
        return filename
    d, t = m.group(1), m.group(2)
    return f"{d[6:8]}.{d[4:6]}.{d[0:4]} {t[0:2]}:{t[2:4]}"
