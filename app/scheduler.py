# -*- coding: utf-8 -*-
"""
scheduler.py — automatyczne backupy wg harmonogramu (per urządzenie).

Tryby (konfigurowane na urządzeniu, w zaszyfrowanej bazie):
  * interval — co N godzin,
  * daily    — codziennie o HH:MM,
  * weekly   — raz w tygodniu, dzień + HH:MM.

UZBRAJANIE: serwer celowo nie przechowuje hasła głównego na dysku, a bez
niego nie odszyfruje bazy urządzeń. Dlatego scheduler uzbraja się przy
pierwszym udanym logowaniu dowolnego użytkownika (hasło trafia do RAM
procesu) i działa do restartu kontenera. Po restarcie harmonogram śpi,
dopóki ktoś się nie zaloguje — UI pokazuje ten stan. To świadomy
kompromis: wygoda vs nietrzymanie klucza do wszystkich FortiGate'ów
na dysku serwera.

Fazowanie: tryb "interval" liczy pierwszy bieg jako uzbrojenie + N godzin
(restart resetuje fazę); daily/weekly zawsze celują w najbliższe
wystąpienie wskazanej godziny, więc restarty im nie przeszkadzają.
"""

from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from .config import load_settings
from .storage import open_storage, open_db_storage
from .devicedb import DeviceDB, Device
from .fortigate import run_backup, device_backup_dir
from .changes import finalize_backup
from .retention import apply_retention
from .jobs import JOBS
from .eventlog import EVENTLOG

TICK_SECONDS = 20            # co ile budzi się pętla
RELOAD_SECONDS = 300         # co ile odświeżana jest baza urządzeń
# Po tylu sekundach od restartu BEZ jakiegokolwiek logowania wrzucamy czerwone
# przypomnienie do dziennika: harmonogram śpi. Domyślnie 1 doba.
IDLE_WARN_SECONDS = 24 * 3600
# Cykliczny przegląd retencji całej floty — siatka bezpieczeństwa dla trybu
# "days" i urządzeń, które chwilowo nie backupują (retencja leci też po każdym
# backupie, ale to nie przycina kopii, gdy backupów brak). Domyślnie raz/dobę.
RETENTION_SWEEP_SECONDS = 24 * 3600

# Ile backupów z harmonogramu może lecieć NARAZ.
#
# Kolejkowanie nie wydłuża okna backupowego w praktyce. Env pozwala podnieść, jeśli magazyn to udźwignie.
SCHED_MAX_PARALLEL = max(1, int(os.environ.get("FORTIBACKUP_SCHED_PARALLEL", "2") or 2))
_SLOTS = threading.BoundedSemaphore(SCHED_MAX_PARALLEL)


def compute_next_run(dev: Device, now: datetime) -> Optional[datetime]:
    """Najbliższy termin backupu dla urządzenia (None = brak harmonogramu)."""
    if not dev.sched_enabled:
        return None
    if dev.sched_mode == "interval":
        return now + timedelta(hours=max(1, int(dev.sched_every_hours or 24)))
    try:
        hh, mm = (int(x) for x in (dev.sched_time or "02:00").split(":")[:2])
        hh, mm = hh % 24, mm % 60
    except ValueError:
        hh, mm = 2, 0
    candidate = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if dev.sched_mode == "daily":
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate
    if dev.sched_mode == "weekly":
        target = int(dev.sched_weekday or 0) % 7
        candidate += timedelta(days=(target - candidate.weekday()) % 7)
        if candidate <= now:
            candidate += timedelta(days=7)
        return candidate
    return None


def _sched_signature(dev: Device) -> Tuple:
    return (dev.sched_enabled, dev.sched_mode, dev.sched_every_hours,
            dev.sched_time, dev.sched_weekday)


class Scheduler:
    def __init__(self):
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._mp: Optional[str] = None
        self._armed_at: Optional[float] = None
        self._devices: List[Device] = []
        self._next: Dict[str, datetime] = {}
        self._sigs: Dict[str, Tuple] = {}
        self._reload_due = 0.0
        self._last_error: Optional[str] = None
        self._started_at: Optional[float] = None   # start procesu (do idle-warn)
        self._idle_warned = False                   # czy ostrzeżono o braku logowania
        self._retention_due = 0.0                   # kiedy następny przegląd retencji

    # -- sterowanie -----------------------------------------------------------

    def start_once(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._started_at = time.time()
            self._idle_warned = False
            self._thread = threading.Thread(target=self._loop, daemon=True,
                                            name="fortibackup-scheduler")
            self._thread.start()

    def arm(self, master_password: str) -> None:
        """Wywoływane po każdym udanym logowaniu."""
        with self._lock:
            first = self._mp is None
            self._mp = master_password
            if first:
                self._armed_at = time.time()
            self._idle_warned = False   # ktoś się zalogował — licznik nieaktualny
            self._reload_due = 0.0  # wymuś świeże wczytanie urządzeń
        # Wpis tylko przy przejściu uśpiony -> aktywny (pierwsze logowanie
        # po starcie), żeby kolejni logujący się nie powtarzali komunikatu.
        # Log poza lockiem — EVENTLOG pisze do pliku.
        if first:
            EVENTLOG.log("success", "Harmonogram aktywny.", "scheduler")

    def disarm(self) -> None:
        with self._lock:
            self._mp = None
            self._armed_at = None
            # licznik idle liczymy od teraz (disarm to celowa akcja, nie restart)
            self._started_at = time.time()
            self._idle_warned = False
            self._next.clear()
            self._sigs.clear()

    def refresh(self) -> None:
        """Wywoływane po zmianach na urządzeniach."""
        with self._lock:
            self._reload_due = 0.0

    def status(self) -> dict:
        with self._lock:
            return {
                "armed": self._mp is not None,
                "armed_at": self._armed_at,
                "last_error": self._last_error,
                "next_runs": {name: dt.isoformat(timespec="minutes")
                              for name, dt in sorted(self._next.items())},
            }

    # -- pętla ------------------------------------------------------------------

    def _loop(self) -> None:
        while True:
            time.sleep(TICK_SECONDS)
            try:
                self._tick()
            except Exception as e:  # noqa: BLE001 — pętla nie może umrzeć
                with self._lock:
                    self._last_error = f"{e}"

    def _tick(self) -> None:
        with self._lock:
            mp = self._mp
            reload_needed = time.time() >= self._reload_due
        if not mp:
            self._maybe_warn_idle()
            return

        if reload_needed:
            self._reload_devices(mp)

        now = datetime.now()
        due: List[Device] = []
        with self._lock:
            for dev in self._devices:
                nxt = self._next.get(dev.name)
                if nxt and nxt <= now:
                    due.append(dev)
                    self._next[dev.name] = compute_next_run(dev, now)
        for dev in due:
            self._run_scheduled(dev, mp)

        self._maybe_sweep_retention(mp)

    def _maybe_sweep_retention(self, mp: str) -> None:
        """Raz na RETENTION_SWEEP_SECONDS przejrzyj retencję CAŁEJ floty.
        Pierwszy przegląd tuż po uzbrojeniu (_retention_due startuje z 0)."""
        with self._lock:
            if time.time() < self._retention_due:
                return
            self._retention_due = time.time() + RETENTION_SWEEP_SECONDS
            devices = [d for d in self._devices
                       if d.retention_mode in ("count", "days", "gfs")]
        if not devices:
            return
        self._run_retention_sweep(devices)

    def _run_retention_sweep(self, devices: List[Device]) -> None:
        job = JOBS.create("Retencja: przegląd urządzeń")
        JOBS.log(job, f"Przegląd retencji dla {len(devices)} urządzeń")

        def work():
            total = 0
            ok = True
            try:
                cfg = load_settings().to_storage_config()
                with open_storage(cfg) as st:
                    for dev in devices:
                        try:
                            total += apply_retention(
                                dev, st,
                                logger=lambda m, n=dev.name: JOBS.log(job, f"[{n}] {m}"))
                        except Exception as e:  # noqa: BLE001 — jedno urządzenie nie psuje reszty
                            JOBS.log(job, f"[{dev.name}] retencja: {e}")
                            ok = False
                JOBS.log(job, f"Przegląd zakończony. Usunięto łącznie {total} kopii.")
                if total:
                    EVENTLOG.log("info",
                                 f"Retencja — przegląd urządzeń: usunięto {total} kopii.",
                                 "scheduler")
            except Exception as e:  # noqa: BLE001
                JOBS.log(job, f"BŁĄD: {e}")
                ok = False
            JOBS.finish(job, ok)

        threading.Thread(target=work, daemon=True).start()

    def _maybe_warn_idle(self) -> None:
        """Nikt nie zalogował się od restartu — po IDLE_WARN_SECONDS wrzuć
        JEDNORAZOWE czerwone przypomnienie, że harmonogram śpi i backupy
        automatyczne nie działają. Pierwsza osoba, która się zaloguje,
        zobaczy to w globalnym dzienniku."""
        with self._lock:
            # uzbrojony (ktoś zalogowany) => harmonogram działa, nie ostrzegaj
            if self._mp is not None or self._idle_warned or self._started_at is None:
                return
            if time.time() - self._started_at < IDLE_WARN_SECONDS:
                return
            self._idle_warned = True
        EVENTLOG.log(
            "error",
            "Od restartu nikt się nie zalogował przez ponad dobę — harmonogram "
            "jest uśpiony, a automatyczne backupy NIE są wykonywane. "
            "Zaloguj się, aby go uruchomić.",
            "scheduler")

    def _reload_devices(self, mp: str) -> None:
        try:
            with open_db_storage() as st:
                db = DeviceDB(st, mp)
                db.load_or_create()
                devices = list(db.devices)
        except Exception as e:  # noqa: BLE001
            with self._lock:
                self._last_error = f"Odświeżenie bazy: {e}"
                self._reload_due = time.time() + 60  # spróbuj za minutę
            EVENTLOG.log("error", f"Harmonogram — odświeżenie bazy urządzeń: {e}",
                         "scheduler")
            return

        now = datetime.now()
        with self._lock:
            self._devices = devices
            self._last_error = None
            self._reload_due = time.time() + RELOAD_SECONDS
            alive = set()
            for dev in devices:
                sig = _sched_signature(dev)
                if dev.sched_enabled:
                    alive.add(dev.name)
                    if self._sigs.get(dev.name) != sig or dev.name not in self._next:
                        self._next[dev.name] = compute_next_run(dev, now)
                self._sigs[dev.name] = sig
            # usuń wpisy urządzeń skasowanych / z wyłączonym harmonogramem
            for name in list(self._next.keys()):
                if name not in alive:
                    del self._next[name]

    def _run_scheduled(self, dev: Device, mp: str) -> None:
        job = JOBS.create(f"Harmonogram: {dev.name}")
        JOBS.log(job, f"Automatyczny backup urządzenia {dev.name}")

        def work():
            ok = True
            # Kolejka: czekamy na wolny slot, żeby nie rzucić całej floty naraz
            # na jeden serwer SFTP (patrz SCHED_MAX_PARALLEL).
            if not _SLOTS.acquire(blocking=False):
                JOBS.log(job, f"[{dev.name}] Czekam na wolny slot backupu...")
                _SLOTS.acquire()
            try:
                cfg = load_settings().to_storage_config()
                with open_storage(cfg) as st:
                    path = run_backup(dev, st, logger=lambda m: JOBS.log(job, m))
                    JOBS.log(job, f"[{dev.name}] OK → {path}")
                    device_dir = device_backup_dir(st, dev)
                    log = lambda m, n=dev.name: JOBS.log(job, f"[{n}] {m}")  # noqa: E731
                    path, collapsed = finalize_backup(st, device_dir, path, log, device=dev)
                    job.ok_count += 1
                    EVENTLOG.log("success",
                                 (f"Harmonogram — bez zmian: {dev.name} → {path}"
                                  if collapsed else
                                  f"Harmonogram — backup OK: {dev.name} → {path}"),
                                 "scheduler")
                    try:
                        apply_retention(dev, st, logger=lambda m, n=dev.name: JOBS.log(job, f"[{n}] {m}"))
                    except Exception as e:  # noqa: BLE001 — nie psuj udanego backupu
                        JOBS.log(job, f"[{dev.name}] Retencja pominięta: {e}")
            except Exception as e:  # noqa: BLE001
                JOBS.log(job, f"[{dev.name}] BŁĄD: {e}")
                job.fail_count += 1
                ok = False
                EVENTLOG.log("error",
                             f"Harmonogram — backup NIEUDANY: {dev.name} — {e}",
                             "scheduler")
            finally:
                _SLOTS.release()      # slot MUSI wrócić, także po wyjątku
            JOBS.finish(job, ok)

        threading.Thread(target=work, daemon=True).start()


SCHEDULER = Scheduler()
