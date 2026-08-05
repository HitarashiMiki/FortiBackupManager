# -*- coding: utf-8 -*-
"""
eventlog.py — trwały, globalny dziennik zdarzeń (niezależny od sesji).

Po co: backupy z harmonogramu tworzą joby w RAM, które giną po restarcie
i nie mają widoku w UI — nieudany nocny backup był praktycznie niewidoczny
(job = "błąd", ale nikt go nie oglądał). Ten dziennik zbiera zdarzenia
WSZYSTKICH backupów (ręcznych i automatycznych) w jednym miejscu, przeżywa
restart kontenera i pozwala sprawdzić "czy coś się nie wykonało" wstecz.

Trwałość: plik JSONL w katalogu danych aplikacji (~/.fortibackup-web,
named volume dockera). NIE na magazynie SFTP — magazyn bywa offline (to
częsta przyczyna błędu backupu), więc byłoby to najgorsze możliwe miejsce.
NIE trzymamy tu sekretów (hasła/tokeny nigdy nie trafiają do logów).

Wydajność: bufor w RAM (szybki odczyt) + append do pliku (trwałość);
co COMPACT_EVERY zapisów plik jest przepisywany z bufora (rotacja do
MAX_EVENTS ostatnich wpisów).
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable, Deque, List, Optional

MAX_EVENTS = 2000            # ile ostatnich wpisów trzymamy (RAM + plik)
COMPACT_EVERY = 100         # co ile zapisów przepisujemy plik (rotacja)
LEVELS = ("info", "success", "warning", "error")


def _data_dir() -> Path:
    return Path.home() / ".fortibackup-web"


class EventLog:
    def __init__(self):
        self._lock = threading.Lock()
        self._buf: Deque[dict] = deque(maxlen=MAX_EVENTS)
        self._loaded = False
        self._writes = 0
        self._subscribers: List[Callable[[dict], None]] = []
        # Licznik zdarzeń od startu procesu. UI odpytuje go przez /api/state,
        # żeby wiedzieć, że doszedł nowy wpis — bez pobierania całego dziennika co kilka sekund.
        # Restart zeruje licznik, więc przeglądarka porównuje przez "różne od
        # poprzedniego", a nie "większe".
        self._seq = 0

    def subscribe(self, callback: Callable[[dict], None]) -> None:
        with self._lock:
            if callback not in self._subscribers:   # idempotentne (restart lifespan)
                self._subscribers.append(callback)

    @property
    def _path(self) -> Path:
        return _data_dir() / "events.jsonl"

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        try:
            if self._path.exists():
                lines = self._path.read_text(encoding="utf-8").splitlines()
                for line in lines[-MAX_EVENTS:]:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        self._buf.append(json.loads(line))
                    except ValueError:
                        continue   # uszkodzona linia nie może wywalić wczytania
        except OSError:
            pass
        self._loaded = True

    def _rewrite_file(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".jsonl.tmp")
            tmp.write_text(
                "\n".join(json.dumps(e, ensure_ascii=False) for e in self._buf) + "\n",
                encoding="utf-8")
            tmp.replace(self._path)   # atomowa podmiana
        except OSError:
            pass

    def _append_file(self, entry: dict) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def log(self, level: str, message: str, source: str = "",
            extra: Optional[dict] = None) -> None:
        entry = {
            "ts": time.time(),
            "level": level if level in LEVELS else "info",
            "source": source,
            "message": message,
        }
        if extra:
            # ustrukturyzowane dane liczbowe (np. ile kopii usunęła retencja),
            # żeby raport mógł je zsumować bez parsowania tekstu komunikatu
            entry["extra"] = extra
        with self._lock:
            self._ensure_loaded()
            over = len(self._buf) >= MAX_EVENTS   # deque wypchnie najstarszy
            self._buf.append(entry)
            self._writes += 1
            self._seq += 1
            # rotacja: gdy bufor jest pełny (plik by rósł w nieskończoność)
            # albo co COMPACT_EVERY zapisów — przepisz plik z bufora
            if over or self._writes >= COMPACT_EVERY:
                self._writes = 0
                self._rewrite_file()
            else:
                self._append_file(entry)
            subscribers = list(self._subscribers)
        for cb in subscribers:
            try:
                cb(dict(entry))
            except Exception:  # noqa: BLE001
                pass

    @property
    def seq(self) -> int:
        """Numer ostatniego zdarzenia (od startu procesu) — puls dla UI."""
        with self._lock:
            return self._seq

    def recent(self, limit: int = 200, level: Optional[str] = None) -> List[dict]:
        with self._lock:
            self._ensure_loaded()
            items = list(self._buf)
        if level in LEVELS:
            items = [e for e in items if e["level"] == level]
        items.reverse()   # najnowsze pierwsze
        return items[:max(1, min(limit, MAX_EVENTS))]

    def clear(self) -> None:
        with self._lock:
            self._buf.clear()
            self._writes = 0
            self._seq += 1        # UI ma zauważyć, że widok się zmienił
            self._loaded = True
            try:
                if self._path.exists():
                    self._path.unlink()
            except OSError:
                pass


EVENTLOG = EventLog()
