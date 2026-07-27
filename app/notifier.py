# -*- coding: utf-8 -*-
"""
notifier.py — powiadomienia email o zdarzeniach z globalnego dziennika.

Domyślnie na skonfigurowany adres lecą wszystkie WARNING i ERROR z dziennika
(EVENTLOG). Wysyłka jest wpięta w EVENTLOG przez subskrypcję (main rejestruje
NOTIFIER.queue_event), więc każde nowe źródło zdarzeń automatycznie korzysta
z powiadomień — bez dokładania wywołań w kółko.

Trzy rzeczy, które łatwo tu zepsuć (i dlaczego są rozwiązane tak, a nie inaczej):

1. PĘTLA SPRZĘŻENIA. Gdyby błąd wysyłki maila logować jako zwykły ERROR do
   EVENTLOG, wyzwoliłby kolejną próbę wysyłki → kolejny błąd → zalew. Dlatego
   błędy własne logujemy ze źródłem "notify", a queue_event takie zdarzenia
   ignoruje.
2. ZALEW MAILI. Backup-all przy padniętym magazynie generuje błąd per
   urządzenie — bez ochrony to dziesiątki maili naraz. Zdarzenia trafiają do
   kolejki, a wątek-flusher co FLUSH_SECONDS wysyła JEDNEGO maila zbiorczego.
3. HASŁO SMTP na dysku. Trzymane w email.json base64-obfuskowane — tak samo
   jak hasło magazynu (świadoma zasłona, nie szyfrowanie; to nie hasło główne).

Konfiguracja: osobny plik ~/.fortibackup-web/email.json (nie settings.json,
który save_setup przepisuje od zera przy zmianie magazynu).
"""

from __future__ import annotations

import json
import smtplib
import threading
import time
from dataclasses import dataclass, asdict, field
from email.message import EmailMessage
from email.utils import formataddr
from pathlib import Path
from typing import List, Optional

from .config import _obf, _deobf
from .eventlog import EVENTLOG

EMAIL_FILE = Path.home() / ".fortibackup-web" / "email.json"

FLUSH_SECONDS = 60          # co ile wątek składa zebrane zdarzenia w jednego maila
SMTP_TIMEOUT = 20           # sekundy na połączenie/operacje SMTP
NOTIFY_SOURCE = "notify"    # źródło zdarzeń wysyłki — IGNOROWANE przez queue_event

# Progi: które poziomy dziennika wyzwalają maila. Waga zdarzenia >= próg.
_LEVEL_WEIGHT = {"info": 0, "success": 0, "warning": 1, "error": 2}
_MIN_LEVEL_THRESHOLD = {"warning": 1, "error": 2}


@dataclass
class EmailConfig:
    enabled: bool = False
    host: str = ""
    port: int = 587
    username: str = ""
    password_obf: str = ""
    use_ssl: bool = False        # SMTPS — połączenie od razu szyfrowane (zwykle :465)
    use_starttls: bool = True    # STARTTLS — upgrade po połączeniu (zwykle :587)
    from_addr: str = ""
    to_addrs: str = ""           # odbiorcy: przecinek / średnik / spacja / nowa linia
    min_level: str = "warning"   # "warning" = warning+error, "error" = tylko error

    def recipients(self) -> List[str]:
        raw = self.to_addrs.replace(";", ",").replace("\n", ",").replace(" ", ",")
        return [a.strip() for a in raw.split(",") if a.strip()]

    def sender(self) -> str:
        return self.from_addr.strip() or self.username.strip()

    def to_public(self) -> dict:
        """Do UI — bez hasła (tylko flaga, czy ustawione)."""
        out = {k: getattr(self, k) for k in
               ("enabled", "host", "port", "username", "use_ssl",
                "use_starttls", "from_addr", "to_addrs", "min_level")}
        out["has_password"] = bool(self.password_obf)
        return out


def load_email_config() -> EmailConfig:
    try:
        data = json.loads(EMAIL_FILE.read_text(encoding="utf-8"))
        known = {f for f in EmailConfig.__dataclass_fields__}
        return EmailConfig(**{k: v for k, v in data.items() if k in known})
    except Exception:  # noqa: BLE001 — brak/uszkodzony plik = domyślna (wyłączona)
        return EmailConfig()


def save_email_config(cfg: EmailConfig) -> None:
    EMAIL_FILE.parent.mkdir(parents=True, exist_ok=True)
    EMAIL_FILE.write_text(json.dumps(asdict(cfg), indent=2, ensure_ascii=False),
                          encoding="utf-8")


def _level_passes(level: str, min_level: str) -> bool:
    return _LEVEL_WEIGHT.get(level, 0) >= _MIN_LEVEL_THRESHOLD.get(min_level, 1)


def send_email(cfg: EmailConfig, subject: str, body: str) -> None:
    """Synchroniczna wysyłka (blokująca) — wołać z wątku. Rzuca wyjątek
    z czytelnym opisem przy błędzie."""
    recipients = cfg.recipients()
    if not cfg.host:
        raise ValueError("Brak adresu serwera SMTP.")
    if not recipients:
        raise ValueError("Brak adresatów powiadomień.")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr(("FortiBackup Web", cfg.sender())) if cfg.sender() else "FortiBackup Web"
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)

    if cfg.use_ssl:
        server = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=SMTP_TIMEOUT)
    else:
        server = smtplib.SMTP(cfg.host, cfg.port, timeout=SMTP_TIMEOUT)
    try:
        server.ehlo()
        if cfg.use_starttls and not cfg.use_ssl:
            server.starttls()
            server.ehlo()
        if cfg.username:
            server.login(cfg.username, _deobf(cfg.password_obf))
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except Exception:  # noqa: BLE001 — zamknięcie nie może maskować właściwego błędu
            pass


def _format_batch(events: List[dict]) -> tuple:
    n = len(events)
    levels = {e["level"] for e in events}
    tag = "BŁĄD" if "error" in levels else "OSTRZEŻENIE"
    if n == 1:
        subject = f"[FortiBackup] {tag}: {events[0]['message'][:80]}"
    else:
        subject = f"[FortiBackup] {n} nowych powiadomień ({tag} i inne)"
    lines = ["Nowe zdarzenia z dziennika FortiBackup Web:", ""]
    for e in events:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.get("ts", time.time())))
        src = f" {e['source']}" if e.get("source") else ""
        lines.append(f"[{ts}]{src} {e['level'].upper()}: {e['message']}")
    return subject, "\n".join(lines)


class Notifier:
    def __init__(self):
        self._lock = threading.Lock()
        self._queue: List[dict] = []
        self._thread: Optional[threading.Thread] = None

    def start_once(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._thread = threading.Thread(target=self._loop, daemon=True,
                                            name="fortibackup-notifier")
            self._thread.start()

    def queue_event(self, entry: dict) -> None:
        """Subskrybent EVENTLOG — wołany po KAŻDYM wpisie. Musi być tani
        i NIGDY nie wywalać logowania."""
        try:
            if entry.get("source") == NOTIFY_SOURCE:
                return                                   # anty-pętla (patrz docstring)
            cfg = load_email_config()
            if not cfg.enabled:
                return
            if not _level_passes(entry.get("level", "info"), cfg.min_level):
                return
            with self._lock:
                self._queue.append(entry)
        except Exception:  # noqa: BLE001 — hook nie może zepsuć EVENTLOG.log
            pass

    def _loop(self) -> None:
        while True:
            time.sleep(FLUSH_SECONDS)
            try:
                self._flush()
            except Exception as e:  # noqa: BLE001 — wątek nie może umrzeć
                EVENTLOG.log("error", f"Notifier: {e}", NOTIFY_SOURCE)

    def _flush(self) -> None:
        with self._lock:
            if not self._queue:
                return
            batch = self._queue[:]
            self._queue.clear()
        cfg = load_email_config()
        if not cfg.enabled:
            return                                       # wyłączono w międzyczasie
        subject, body = _format_batch(batch)
        try:
            send_email(cfg, subject, body)
        except Exception as e:  # noqa: BLE001
            # źródło "notify" => queue_event to ZIGNORUJE (bez pętli)
            EVENTLOG.log("error",
                         f"Wysyłka powiadomienia email nie powiodła się: {e}",
                         NOTIFY_SOURCE)

    def send_test(self, cfg: EmailConfig) -> None:
        """Testowa wiadomość z przycisku w ustawieniach (synchronicznie —
        endpoint chce od razu wiedzieć, czy się udało)."""
        send_email(cfg, "[FortiBackup] Wiadomość testowa",
                   "To jest testowe powiadomienie z FortiBackup Web.\n"
                   "Jeśli je widzisz, konfiguracja email działa poprawnie.")


NOTIFIER = Notifier()
