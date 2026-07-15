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
from typing import Dict, Optional

from .diff import normalize_config
from .storage import RemoteStorage, StorageError

META_FILENAME = ".fbk-meta.json"


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
    new_name = posixpath.basename(new_path)
    candidates = [f.name for f in storage.list_files(device_dir)
                  if f.name != new_name and not f.name.startswith(".")]
    prev_name = max((n for n in candidates if n < new_name), default=None)
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


def detect_and_log(storage: RemoteStorage, device_dir: str, new_path: str,
                   log) -> None:
    """Wrapper dla jobów backupu: porównaj, zaloguj, 
    nieudana detekcja zmian nie może unieważnić udanego backupu."""
    try:
        changed = record_change_flag(storage, device_dir, new_path)
    except Exception as e:  # noqa: BLE001
        log(f"Nie udało się porównać z poprzednią wersją: {e}")
        return
    if changed is True:
        log("Wykryto zmiany konfiguracji względem poprzedniej wersji")
    elif changed is False:
        log("Brak zmian względem poprzedniej wersji")
