# -*- coding: utf-8 -*-
"""
version.py — wykrywanie dostępności nowej wersji aplikacji.

Uruchomiona wersja jest wbudowana w obraz (plik VERSION, kopiowany przy
docker build). Wątek w tle co CHECK_INTERVAL pyta GitHub o najnowszy RELEASE
i porównuje semver — gdy zdalny > lokalny, UI pokazuje baner „nowa wersja".

Workflow wydania (po stronie Jakuba):
  1. podbij plik VERSION (np. 1.5.0 -> 1.6.0), commit + push na main,
  2. utwórz Release na GitHub z tagiem o TEJ SAMEJ wersji (v1.6.0 lub 1.6.0).
Działające instancje (ze starszym VERSION w obrazie) wykryją nowszy release
i pokażą baner, dopóki nie zrobisz `git pull && docker compose up -d --build`.

Sieć: kontener bez dostępu do GitHuba po prostu nie pokaże banera (błąd jest
cichy). Sprawdzanie można wyłączyć env FORTIBACKUP_UPDATE_CHECK=false; repo
nadpisać przez FORTIBACKUP_REPO="owner/nazwa".
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.request
from pathlib import Path
from typing import Optional, Tuple

CHECK_INTERVAL = 6 * 3600      # co ile sprawdzać najnowszy release
FIRST_CHECK_DELAY = 10         # krótka zwłoka po starcie (nie blokuj bootu)
HTTP_TIMEOUT = 10
DEFAULT_REPO = "HitarashiMiki/FortiBackupManager"

_RE_SEMVER = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def read_current_version() -> str:
    """Wersja uruchomiona — z pliku VERSION (obraz/dev). '?' gdy brak."""
    # kolejno: obok kodu (repo root), katalog roboczy, /app (kontener)
    candidates = [
        Path(__file__).resolve().parent.parent / "VERSION",
        Path.cwd() / "VERSION",
        Path("/app/VERSION"),
    ]
    for p in candidates:
        try:
            txt = p.read_text(encoding="utf-8").strip()
            if txt:
                return txt
        except OSError:
            continue
    return "?"


def parse_semver(text: str) -> Optional[Tuple[int, int, int]]:
    """'v1.6.0' / '1.6' -> (1,6,0). None, gdy nie da się rozpoznać."""
    if not text:
        return None
    m = _RE_SEMVER.search(text)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0))


def is_newer(latest: str, current: str) -> bool:
    """Czy `latest` jest nowszą wersją niż `current` (porównanie semver).
    Przy niejednoznacznych wersjach zwraca False — lepiej nie krzyczeć."""
    lv, cv = parse_semver(latest), parse_semver(current)
    if lv is None or cv is None:
        return False
    return lv > cv


class VersionChecker:
    def __init__(self):
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._current = read_current_version()
        self._latest: Optional[str] = None
        self._url: Optional[str] = None        # link do release (dla UI)
        self._last_checked: Optional[float] = None
        self._error: Optional[str] = None
        self._enabled = _env_bool("FORTIBACKUP_UPDATE_CHECK", True)
        self._repo = os.environ.get("FORTIBACKUP_REPO", DEFAULT_REPO).strip()

    def start_once(self) -> None:
        if not self._enabled:
            return
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._thread = threading.Thread(target=self._loop, daemon=True,
                                            name="fortibackup-version")
            self._thread.start()

    def _loop(self) -> None:
        time.sleep(FIRST_CHECK_DELAY)
        while True:
            self.check_now()
            time.sleep(CHECK_INTERVAL)

    def check_now(self) -> None:
        latest, url, err = self._fetch_latest()
        with self._lock:
            self._last_checked = time.time()
            if err:
                self._error = err
            else:
                self._latest = latest
                self._url = url
                self._error = None

    def _fetch_latest(self):
        api = f"https://api.github.com/repos/{self._repo}/releases/latest"
        req = urllib.request.Request(api, headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "FortiBackup-Web-update-check",
        })
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            tag = (data.get("tag_name") or data.get("name") or "").strip()
            url = data.get("html_url") or f"https://github.com/{self._repo}/releases"
            if not tag:
                return None, None, "brak tagu w najnowszym release"
            return tag, url, None
        except Exception as e:  # noqa: BLE001 — brak sieci/404/limit = cichy błąd
            return None, None, f"{e}"

    def status(self) -> dict:
        with self._lock:
            update = bool(self._latest) and is_newer(self._latest, self._current)
            return {
                "current": self._current,
                "latest": self._latest,
                "update_available": update,
                "release_url": self._url or f"https://github.com/{self._repo}/releases",
                "last_checked": self._last_checked,
                "enabled": self._enabled,
            }


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


VERSION_CHECKER = VersionChecker()
APP_VERSION = VERSION_CHECKER._current
