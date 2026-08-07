# -*- coding: utf-8 -*-
"""
security.py — bezpieczeństwo aplikacji webowej.

1. Sesje SERVER-SIDE: cookie przeglądarki zawiera wyłącznie losowy token;
   hasło główne żyje tylko w pamięci procesu serwera. (Starlette
   SessionMiddleware trzyma dane sesji w cookie po stronie klienta —
   podpisanym, ale NIEzaszyfrowanym — więc trzymanie tam master password
   oznaczałoby rozdawanie go każdemu, kto zobaczy cookie.)

2. Secret do podpisu cookie generowany losowo przy pierwszym starcie
   i trzymany w katalogu danych (wolumen dockera) — nie w repo.

3. Prosty rate limiter na logowanie (ochrona przed brute-force
   hasła głównego).

4. Walidacja ścieżek z URL-i — endpointy plikowe mogą dotykać wyłącznie
   katalogu backups/ pod base_path (żadnych "..", żadnego devices.db).

5. Rejestr sekretów + usuwanie ich z logów. Ostatnia linia obrony: żaden
   komunikat trafiający do dziennika, joba czy maila nie ma prawa zawierać
   hasła.
"""

from __future__ import annotations

import posixpath
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

DATA_DIR = Path.home() / ".fortibackup-web"
SECRET_FILE = DATA_DIR / "session_secret"

SESSION_TTL = 8 * 3600          # 8h (dzień pracy)
LOGIN_MAX_ATTEMPTS = 5          # prób…
LOGIN_WINDOW = 60               # …na minutę na IP


# --------------------------------------------------------------------------- #
#  Secret
# --------------------------------------------------------------------------- #

def get_or_create_secret() -> str:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if SECRET_FILE.exists():
        secret = SECRET_FILE.read_text(encoding="utf-8").strip()
        if secret:
            return secret
    secret = secrets.token_urlsafe(48)
    SECRET_FILE.write_text(secret, encoding="utf-8")
    try:
        SECRET_FILE.chmod(0o600)
    except OSError:
        pass
    return secret


# --------------------------------------------------------------------------- #
#  Server-side session
# --------------------------------------------------------------------------- #

@dataclass
class _Session:
    master_password: str
    expires: float


class SessionStore:
    """Token (w cookie) -> hasło główne (tylko w RAM serwera)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._sessions: Dict[str, _Session] = {}

    def create(self, master_password: str) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._prune()
            self._sessions[token] = _Session(master_password, time.time() + SESSION_TTL)
        return token

    def get_master_password(self, token: Optional[str]) -> Optional[str]:
        if not token:
            return None
        with self._lock:
            s = self._sessions.get(token)
            if not s:
                return None
            if s.expires < time.time():
                del self._sessions[token]
                return None
            s.expires = time.time() + SESSION_TTL
            return s.master_password

    def destroy(self, token: Optional[str]) -> None:
        if not token:
            return
        with self._lock:
            self._sessions.pop(token, None)

    def _prune(self) -> None:
        now = time.time()
        dead = [t for t, s in self._sessions.items() if s.expires < now]
        for t in dead:
            del self._sessions[t]


SESSIONS = SessionStore()


# --------------------------------------------------------------------------- #
#  Rate limit login
# --------------------------------------------------------------------------- #

class LoginRateLimiter:
    def __init__(self, max_attempts: int = LOGIN_MAX_ATTEMPTS, window: int = LOGIN_WINDOW):
        self.max_attempts = max_attempts
        self.window = window
        self._lock = threading.Lock()
        self._attempts: Dict[str, list] = {}

    def allow(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            hist = [t for t in self._attempts.get(ip, []) if now - t < self.window]
            self._attempts[ip] = hist
            if len(hist) >= self.max_attempts:
                return False
            hist.append(now)
            return True


LOGIN_LIMITER = LoginRateLimiter()


# --------------------------------------------------------------------------- #
#  Rejestr sekretów — usuwanie haseł z logów
# --------------------------------------------------------------------------- #

# Hasła, które aplikacja gdzieś podaje dalej (magazyn, konta SSH urządzeń,
# tokeny API).
_SECRETS: set = set()
_SECRETS_LOCK = threading.Lock()

# Krótkie ciągi ("22", "abc") wycieralibyśmy z połowy komunikatów, robiąc
# z logów sieczkę. Poniżej tej długości sekretu nie rejestrujemy.
MIN_SECRET_LEN = 5
SECRET_MASK = "***"


def register_secret(value: Optional[str]) -> None:
    """Zgłasza hasło/token do usuwania z logów."""
    if not value or len(value) < MIN_SECRET_LEN:
        return
    with _SECRETS_LOCK:
        _SECRETS.add(value)


def scrub_secrets(text: str) -> str:
    """Usuwa zarejestrowane sekrety. Uruchamiane przy KAŻDYM wpisie do dziennika
    i loga joba — świadomie na końcu łańcucha."""
    if not text:
        return text
    with _SECRETS_LOCK:
        secrets_snapshot = tuple(_SECRETS)
    for s in secrets_snapshot:
        if s in text:
            text = text.replace(s, SECRET_MASK)
    return text


def clear_secrets() -> None:
    """Czyści rejestr (wylogowanie wszystkich / testy)."""
    with _SECRETS_LOCK:
        _SECRETS.clear()


# --------------------------------------------------------------------------- #
#  Backup directory validation
# --------------------------------------------------------------------------- #

class PathTraversalError(Exception):
    pass


def safe_backup_path(base_path: str, raw_path: str) -> str:
    """Zwraca znormalizowaną ścieżkę, jeśli leży wewnątrz <base>/backups/.

    Bez tej walidacji zalogowany użytkownik mógłby przez /api/view,
    /api/download i DELETE /api/version czytać i kasować DOWOLNE pliki
    dostępne dla konta magazynu — z zaszyfrowaną bazą devices.db włącznie.
    """
    if not raw_path.startswith("/"):
        raw_path = "/" + raw_path
    norm = posixpath.normpath(raw_path)
    if ".." in norm.split("/"):
        raise PathTraversalError("Niedozwolona ścieżka.")
    allowed_prefix = posixpath.normpath(posixpath.join(base_path, "backups")) + "/"
    if not norm.startswith(allowed_prefix):
        raise PathTraversalError("Ścieżka poza katalogiem backupów.")
    return norm
