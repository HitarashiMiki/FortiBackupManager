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

import ipaddress
import json
import posixpath
import secrets
import threading
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, List, Optional

DATA_DIR = Path.home() / ".fortibackup-web"
SECRET_FILE = DATA_DIR / "session_secret"

SESSION_TTL = 8 * 3600          # 8h (dzień pracy) — domyślka, patrz SecurityConfig
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


def _ttl() -> int:
    """Długość sesji z konfiguracji bezpieczeństwa (z cache w LOGIN_GUARD —
    to leci przy KAŻDYM requeście, więc nie może czytać pliku za każdym razem)."""
    try:
        return LOGIN_GUARD.cfg.session_ttl_hours * 3600
    except Exception:  # noqa: BLE001 — brak/uszkodzona konfiguracja nie może wylogować wszystkich
        return SESSION_TTL


class SessionStore:
    """Token (w cookie) -> hasło główne (tylko w RAM serwera)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._sessions: Dict[str, _Session] = {}

    def create(self, master_password: str) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._prune()
            self._sessions[token] = _Session(master_password, time.time() + _ttl())
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
            s.expires = time.time() + _ttl()
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
#  Konfiguracja bezpieczeństwa (security.json)
# --------------------------------------------------------------------------- #
# OSOBNY plik, tak jak email.json — `save_setup` przepisuje settings.json od
# zera i skasowałby te ustawienia.

SECURITY_FILE_NAME = "security.json"

# Tryb inteligentny ma działanie ZAHARDKODOWANE (UI wyszarza wtedy ręczne pola),
# żeby nie dało się go skonfigurować w sposób, który go unieszkodliwia.
SMART_MAX_ATTEMPTS = 5           # tyle nieudanych prób = ban
SMART_BASE_MINUTES = 5           # długość "normalnego" bana
SMART_FACTOR = 4                 # mnożnik po wyczerpaniu banów łagodnych
SMART_MAX_MINUTES = 24 * 60      # sufit — dłuższy ban nic nie wnosi
# Po tylu godzinach bez ani jednej nieudanej próby historia banów danego IP
# jest kasowana (eskalacja startuje od nowa).
BAN_HISTORY_RESET_HOURS = 24


@dataclass
class SecurityConfig:
    # --- rate limit / blokowanie IP ---
    max_attempts: int = 5            # nieudanych prób…
    window_minutes: int = 1          # …w tym oknie czasu
    ban_minutes: int = 15            # na tyle blokujemy IP
    smart_ban: bool = False          # tryb inteligentny (eskalacja, patrz wyżej)
    smart_grace_bans: int = 2        # ile pierwszych banów jest "normalnych"
    whitelist: List[str] = field(default_factory=list)   # IP lub sieci (CIDR)
    # --- sesja ---
    session_ttl_hours: int = 8
    # --- hasło główne ---
    min_master_password_length: int = 8
    # --- audyt ---
    log_login_attempts: bool = True  # nieudane/udane logowania do dziennika
    # --- połączenia z urządzeniami ---
    verify_device_tls: bool = False  # weryfikuj certyfikat FortiGate przy api_pull

    def clamp(self) -> "SecurityConfig":
        """Wartości z formularza mogą być bez sensu — przycinamy do zakresu,
        w którym mechanizm nadal chroni (np. 0 prób = nikt się nie zaloguje)."""
        self.max_attempts = max(1, min(int(self.max_attempts), 100))
        self.window_minutes = max(1, min(int(self.window_minutes), 1440))
        self.ban_minutes = max(1, min(int(self.ban_minutes), SMART_MAX_MINUTES))
        self.smart_grace_bans = max(0, min(int(self.smart_grace_bans), 10))
        self.session_ttl_hours = max(1, min(int(self.session_ttl_hours), 24 * 30))
        self.min_master_password_length = max(8, min(int(self.min_master_password_length), 128))
        self.whitelist = [e for e in (s.strip() for s in self.whitelist) if e]
        return self


def _security_file() -> Path:
    # Ścieżka liczona przy każdym użyciu (nie na imporcie) — katalog danych
    # zależy od HOME, a testy podmieniają go po zaimportowaniu modułu.
    return Path.home() / ".fortibackup-web" / SECURITY_FILE_NAME


def load_security_config() -> SecurityConfig:
    try:
        data = json.loads(_security_file().read_text(encoding="utf-8"))
        known = {f for f in SecurityConfig.__dataclass_fields__}
        return SecurityConfig(**{k: v for k, v in data.items() if k in known}).clamp()
    except Exception:  # noqa: BLE001 — brak pliku / śmieci = wracamy do domyślek
        return SecurityConfig()


def save_security_config(cfg: SecurityConfig) -> None:
    cfg.clamp()
    path = _security_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(asdict(cfg), indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)
    LOGIN_GUARD.reload_config()


def validate_whitelist_entry(entry: str) -> str:
    """Zwraca znormalizowany wpis whitelisty albo rzuca ValueError.
    Akceptuje pojedyncze IP ("10.0.0.5") i sieci ("10.0.0.0/24"), v4 i v6."""
    entry = (entry or "").strip()
    if not entry:
        raise ValueError("Pusty wpis.")
    try:
        # strict=False pozwala podać adres hosta z maską (10.0.0.5/24)
        return str(ipaddress.ip_network(entry, strict=False))
    except ValueError as e:
        raise ValueError(f"'{entry}' to nie jest adres IP ani sieć (np. 10.0.0.0/24).") from e


def session_ttl_seconds() -> int:
    return load_security_config().session_ttl_hours * 3600


# --------------------------------------------------------------------------- #
#  Ochrona logowania: rate limit + blokada IP
# --------------------------------------------------------------------------- #

@dataclass
class _IpState:
    fails: List[float] = field(default_factory=list)   # znaczniki nieudanych prób
    banned_until: float = 0.0
    ban_count: int = 0                                  # ile razy to IP już oberwało
    last_fail: float = 0.0


class LoginGuard:
    """Rate limit logowania z blokadą po adresie IP.

    Dwa tryby:
      * ręczny — N nieudanych prób w oknie czasu = ban na stałą liczbę minut,
      * inteligentny — jeśli ban nie zniechęca (kolejne nieudane próby po jego
        wygaśnięciu), czas blokady rośnie ×4 z każdym kolejnym banem.

    Whitelist (IP/CIDR) omija mechanizm — na wypadek gdyby admin zablokował
    sam siebie z sieci zarządzania.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._ips: Dict[str, _IpState] = {}
        self._cfg = SecurityConfig()
        self._cfg_loaded = False

    # -- konfiguracja ---------------------------------------------------------

    @property
    def cfg(self) -> SecurityConfig:
        if not self._cfg_loaded:
            self._cfg = load_security_config()
            self._cfg_loaded = True
        return self._cfg

    def reload_config(self) -> None:
        with self._lock:
            self._cfg_loaded = False

    # -- whitelist ------------------------------------------------------------

    def is_whitelisted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for entry in self.cfg.whitelist:
            try:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue      # zły wpis nie może wywalić logowania
        return False

    # -- właściwa logika ------------------------------------------------------

    def _ban_seconds(self, st: _IpState) -> int:
        cfg = self.cfg
        if not cfg.smart_ban:
            return cfg.ban_minutes * 60
        # ban_count zawiera już bieżący ban
        over = max(0, st.ban_count - cfg.smart_grace_bans)
        minutes = SMART_BASE_MINUTES * (SMART_FACTOR ** over)
        return int(min(minutes, SMART_MAX_MINUTES) * 60)

    def _max_attempts(self) -> int:
        cfg = self.cfg
        return SMART_MAX_ATTEMPTS if cfg.smart_ban else cfg.max_attempts

    def check(self, ip: str) -> int:
        """0 = wolno próbować; >0 = sekundy pozostałe do końca blokady."""
        if self.is_whitelisted(ip):
            return 0
        now = time.time()
        with self._lock:
            st = self._ips.get(ip)
            if not st:
                return 0
            if st.banned_until > now:
                return int(st.banned_until - now) + 1
            return 0

    def record_failure(self, ip: str) -> int:
        """Zapisuje nieudaną próbę. Zwraca długość bana w sekundach."""
        if self.is_whitelisted(ip):
            return 0
        now = time.time()
        cfg = self.cfg
        window = (cfg.window_minutes * 60) if not cfg.smart_ban else LOGIN_WINDOW
        with self._lock:
            st = self._ips.setdefault(ip, _IpState())
            # historia banów starzeje się — po dobie spokoju eskalacja od nowa
            if st.last_fail and now - st.last_fail > BAN_HISTORY_RESET_HOURS * 3600:
                st.ban_count = 0
            st.last_fail = now
            st.fails = [t for t in st.fails if now - t < window]
            st.fails.append(now)
            if len(st.fails) < self._max_attempts():
                return 0
            st.ban_count += 1
            seconds = self._ban_seconds(st)
            st.banned_until = now + seconds
            st.fails.clear()          # licznik od zera, ban i tak trwa
            return seconds

    def record_success(self, ip: str) -> None:
        """Udane logowanie — kasujemy licznik prób tego IP.
        Historię banów ZOSTAWIAMY."""
        with self._lock:
            st = self._ips.get(ip)
            if st:
                st.fails.clear()

    # -- podgląd i sterowanie dla UI -----------------------------------------

    def active_bans(self) -> List[dict]:
        now = time.time()
        with self._lock:
            return sorted(
                ({"ip": ip, "seconds_left": int(st.banned_until - now) + 1,
                  "ban_count": st.ban_count}
                 for ip, st in self._ips.items() if st.banned_until > now),
                key=lambda b: -b["seconds_left"])

    def recent_offenders(self) -> List[dict]:
        """IP z historią banów — kontekst dla admina."""
        now = time.time()
        with self._lock:
            return sorted(
                ({"ip": ip, "ban_count": st.ban_count,
                  "banned": st.banned_until > now,
                  "seconds_left": max(0, int(st.banned_until - now)),
                  "last_fail": st.last_fail}
                 for ip, st in self._ips.items() if st.ban_count or st.fails),
                key=lambda b: -b["last_fail"])

    def unban(self, ip: str) -> bool:
        with self._lock:
            st = self._ips.get(ip)
            if not st:
                return False
            was = st.banned_until > time.time()
            st.banned_until = 0.0
            st.fails.clear()
            return was

    def reset(self) -> None:
        """Czyści cały stan (testy, „odblokuj wszystkich" w UI)."""
        with self._lock:
            self._ips.clear()


LOGIN_GUARD = LoginGuard()


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
