# -*- coding: utf-8 -*-
"""
retention.py — automatyczne usuwanie starych kopii konfiguracji (per urządzenie).

Przy codziennych backupach dużej floty pliki narastają. Retencja przycina je
po każdym udanym backupie. Trzy tryby (pole Device.retention_mode):

  * "count" — trzymaj N NAJNOWSZYCH kopii, starsze usuń.
  * "days"  — usuń kopie starsze niż N dni.
  * "gfs"   — Grandfather-Father-Son: po jednej reprezentatywnej (najnowszej)
              kopii z ostatnich N dni, M tygodni i K miesięcy.

ZASADY BEZPIECZEŃSTWA (KRYTYCZNE — retencja usuwa pliki z magazynu):

1. WHITELIST, nie blacklist. Kandydatem do usunięcia jest WYŁĄCZNIE plik, którego
   nazwa jest rozpoznana jako backup FortiGate: `..._YYYYmmdd_HHMMSS.conf`.
   Cokolwiek innego (devices.db, settings.json, session_secret, .fbk-meta.json,
   pliki bez timestampu lub o innym rozszerzeniu) NIGDY nie jest kandydatem —
   jest całkowicie pomijane, nie tylko „zachowywane".
   Dzięki temu, nawet gdyby taki plik trafił do katalogu backupów, retencja go
   nie dotknie. NIE polegamy na mtime (który dałby cudzemu plikowi fałszywy
   „czas kopii"); czas bierzemy TYLKO z nazwy pliku backupu.

2. Retencja NIGDY nie usuwa najnowszej kopii — nawet jeśli reguła by na to
   wskazywała (np. "usuń starsze niż 7 dni", a urządzenie miesiąc nie backupowało).

3. apply_retention dokłada twarde bariery przy samym usuwaniu (patrz niżej):
   ponowna kontrola whitelisty, wykluczenie nazwy bazy urządzeń i ograniczenie
   do katalogu backupów danego urządzenia.
"""

from __future__ import annotations

import posixpath
import re
from datetime import datetime, timedelta
from typing import List, Optional, Callable

from .devicedb import Device, DB_FILENAME
from .fortigate import device_backup_dir
from .storage import RemoteStorage, RemoteFile

Logger = Callable[[str], None]

RETENTION_MODES = ("off", "count", "days", "gfs")

# Timestamp w nazwie backupu: ..._YYYYmmdd_HHMMSS
_RE_TS = re.compile(r"_(\d{8}_\d{6})$")
# WHITELIST pliku backupu: dowolna nazwa + _YYYYmmdd_HHMMSS + DOKŁADNIE ".conf".
# Tylko takie pliki wolno w ogóle rozważać do usunięcia.
_RE_BACKUP = re.compile(r".+_\d{8}_\d{6}\.conf\Z", re.IGNORECASE)


def is_backup_file(name: str) -> bool:
    """Czy nazwa to NA PEWNO plik backupu FortiGate (whitelist)."""
    if not name or name.startswith("."):
        return False
    if name == DB_FILENAME:               # baza urządzeń — nigdy
        return False
    return bool(_RE_BACKUP.match(name))


def parse_backup_time(f: RemoteFile) -> Optional[datetime]:
    """Czas kopii WYŁĄCZNIE z nazwy pliku backupu (bez fallbacku na mtime —
    mtime nadałby cudzemu plikowi fałszywy czas i uczynił go kandydatem)."""
    stem = f.name[:-5] if f.name.lower().endswith(".conf") else f.name
    m = _RE_TS.search(stem)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y%m%d_%H%M%S")
        except ValueError:
            pass
    return None


def select_for_deletion(files: List[RemoteFile], device: Device,
                        now: Optional[datetime] = None) -> List[RemoteFile]:
    """Czysta logika: które pliki usunąć wg trybu retencji urządzenia.
    Rozważa TYLKO pliki backupu (whitelist). Zawsze zachowuje najnowszą kopię."""
    now = now or datetime.now()
    mode = device.retention_mode
    if mode not in ("count", "days", "gfs"):
        return []
    # WHITELIST: tylko rozpoznane backupy z poprawnym czasem z nazwy
    dated = [(parse_backup_time(f), f) for f in files if is_backup_file(f.name)]
    dated = [(t, f) for t, f in dated if t is not None]
    dated.sort(key=lambda p: p[0], reverse=True)   # najnowsze pierwsze
    if len(dated) <= 1:
        return []                        # jedna (lub zero) kopii — nie ma co usuwać

    keep = set()
    keep.add(id(dated[0][1]))            # najnowsza — ZAWSZE zostaje

    if mode == "count":
        n = max(1, int(device.retention_count or 1))
        for _, f in dated[:n]:
            keep.add(id(f))

    elif mode == "days":
        days = max(1, int(device.retention_days or 1))
        cutoff = now - timedelta(days=days)
        for t, f in dated:
            if t is not None and t >= cutoff:
                keep.add(id(f))

    elif mode == "gfs":
        keep |= _gfs_keep(dated, device)

    return [f for _, f in dated if id(f) not in keep]


def _gfs_keep(dated, device: Device) -> set:
    """Zbiór id() plików do zachowania wg Grandfather-Father-Son.
    Dla każdego okresu (dzień/tydzień/miesiąc) zostaje NAJNOWSZA kopia."""
    keep = set()

    def newest_per_bucket(bucket_key, limit):
        if limit <= 0:
            return
        buckets = {}
        # dated jest malejąco (najnowsze pierwsze) → pierwszy trafiony w danym
        # kubełku jest najnowszy z tego okresu
        for t, f in dated:
            if t is None:
                continue
            k = bucket_key(t)
            if k not in buckets:
                buckets[k] = f
        for k in sorted(buckets, reverse=True)[:limit]:
            keep.add(id(buckets[k]))

    newest_per_bucket(lambda t: t.date(), int(device.gfs_daily or 0))
    newest_per_bucket(lambda t: t.isocalendar()[:2], int(device.gfs_weekly or 0))
    newest_per_bucket(lambda t: (t.year, t.month), int(device.gfs_monthly or 0))
    return keep


def apply_retention(device: Device, storage: RemoteStorage,
                    logger: Optional[Logger] = None) -> int:
    """Usuwa nadmiarowe kopie urządzenia z magazynu. Zwraca liczbę usuniętych.
    Best-effort — pojedynczy błąd usuwania nie przerywa reszty."""
    if device.retention_mode not in ("count", "days", "gfs"):
        return 0
    base = device_backup_dir(storage, device)
    files = storage.list_files(base)
    backups = [f for f in files if is_backup_file(f.name)]
    to_delete = select_for_deletion(files, device)

    # Katalog backupów urządzenia jako granica: usuwamy tylko w jego obrębie.
    # Normalizacja separatorów — LocalStorage na Windows miesza \ i / (na
    # zdalnym SFTP/FTP ścieżki są zawsze posixowe, ale bariera ma być odporna).
    def _norm(p: str) -> str:
        return p.replace("\\", "/")
    safe_prefix = _norm(base).rstrip("/") + "/"
    removed = 0
    for f in to_delete:
        # POTRÓJNA bariera przy samym usuwaniu (obok whitelisty w select):
        # 1) nazwa musi być rozpoznanym backupem (wyklucza devices.db, settings itd.),
        # 2) plik musi leżeć w katalogu backupów TEGO urządzenia,
        # 3) basename nie może być nazwą bazy urządzeń.
        base_name = posixpath.basename(f.path)
        if not is_backup_file(f.name) or not is_backup_file(base_name):
            if logger:
                logger(f"Retencja: POMINIĘTO {f.name}")
            continue
        if base_name == DB_FILENAME:
            continue
        if not _norm(f.path).startswith(safe_prefix):
            if logger:
                logger(f"Retencja: POMINIĘTO {f.path}")
            continue
        try:
            storage.delete(f.path)
            removed += 1
        except Exception as e:  # noqa: BLE001
            if logger:
                logger(f"Retencja: nie udało się usunąć {f.name}: {e}")
    if removed and logger:
        logger(f"Retencja: usunięto {removed} starych kopii "
                f"(pozostało {len(backups) - removed}).")
    return removed
