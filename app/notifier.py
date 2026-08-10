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
from datetime import datetime, timedelta
from email.message import EmailMessage
from email.utils import formataddr
from pathlib import Path
from typing import List, Optional

from .config import _obf, _deobf
from .eventlog import EVENTLOG

EMAIL_FILE = Path.home() / ".fortibackup-web" / "email.json"
REPORT_STATE_FILE = Path.home() / ".fortibackup-web" / "notify_state.json"

FLUSH_SECONDS = 60          # co ile wątek składa zebrane zdarzenia w jednego maila
SMTP_TIMEOUT = 20           # sekundy na połączenie/operacje SMTP
NOTIFY_SOURCE = "notify"    # źródło zdarzeń wysyłki — IGNOROWANE przez queue_event
REPORT_RETRY_SECONDS = 1800 # po nieudanej wysyłce raportu ponów nie częściej niż co 30 min

_BACKUP_SOURCES = ("backup", "scheduler")
RETENTION_SOURCE = "retention"

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
    # Powiadomienia o błędach (warning/error z dziennika):
    to_addrs: str = ""           # odbiorcy powiadomień: przecinek/średnik/spacja/nl
    min_level: str = "warning"   # "warning" = warning+error, "error" = tylko error
    # Zbiorczy raport wykonanych backupów (niezależny od powiadomień):
    report: str = "off"          # "off" | "daily" | "weekly"
    report_time: str = "08:00"   # godzina wysyłki raportu (HH:MM)
    report_weekday: int = 0      # dla "weekly": 0 = poniedziałek
    report_to_addrs: str = ""    # odbiorcy raportu — NIEZALEŻNI od powiadomień

    def recipients(self) -> List[str]:
        """Odbiorcy powiadomień o błędach."""
        return _parse_addrs(self.to_addrs)

    def report_recipients(self) -> List[str]:
        """Odbiorcy raportu zbiorczego."""
        return _parse_addrs(self.report_to_addrs)

    def sender(self) -> str:
        return self.from_addr.strip() or self.username.strip()

    def to_public(self) -> dict:
        """Do UI — bez hasła (tylko flaga, czy ustawione)."""
        out = {k: getattr(self, k) for k in
               ("enabled", "host", "port", "username", "use_ssl",
                "use_starttls", "from_addr", "to_addrs", "min_level",
                "report", "report_time", "report_weekday", "report_to_addrs")}
        out["has_password"] = bool(self.password_obf)
        return out


def _parse_addrs(raw: str) -> List[str]:
    raw = (raw or "").replace(";", ",").replace("\n", ",").replace(" ", ",")
    return [a.strip() for a in raw.split(",") if a.strip()]


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


def send_email(cfg: EmailConfig, subject: str, body: str,
               recipients: Optional[List[str]] = None) -> None:
    """Synchroniczna wysyłka (blokująca) — wołać z wątku. Rzuca wyjątek
    z czytelnym opisem przy błędzie. `recipients` jawnie, bo powiadomienia
    i raporty mają OSOBNE listy odbiorców (domyślnie: odbiorcy powiadomień)."""
    recipients = cfg.recipients() if recipients is None else recipients
    if not cfg.host:
        raise ValueError("Brak adresu serwera SMTP.")
    if not recipients:
        raise ValueError("Brak adresatów.")

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


# --------------------------------------------------------------------------- #
#  Raport zbiorczy backupów (dzienny / tygodniowy)
# --------------------------------------------------------------------------- #

def _load_report_state() -> dict:
    try:
        return json.loads(REPORT_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def _save_report_state(state: dict) -> None:
    try:
        REPORT_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        REPORT_STATE_FILE.write_text(json.dumps(state), encoding="utf-8")
    except OSError:
        pass


def _parse_hhmm(text: str) -> tuple:
    try:
        hh, mm = (int(x) for x in (text or "08:00").split(":")[:2])
        return hh % 24, mm % 60
    except (ValueError, AttributeError):
        return 8, 0


def last_scheduled(now: datetime, mode: str, hh: int, mm: int,
                   weekday: int) -> Optional[datetime]:
    """Ostatni zaplanowany moment raportu. Odporny na restart."""
    cand = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if mode == "daily":
        if cand > now:
            cand -= timedelta(days=1)
        return cand
    if mode == "weekly":
        cand -= timedelta(days=(now.weekday() - int(weekday)) % 7)
        if cand > now:
            cand -= timedelta(days=7)
        return cand
    return None


def _collect_by_source(sources, period_seconds: float,
                       now_ts: Optional[float]) -> List[dict]:
    now_ts = now_ts if now_ts is not None else time.time()
    cutoff = now_ts - period_seconds
    events = [e for e in EVENTLOG.recent(limit=10_000)
              if e.get("source") in sources and e.get("ts", 0) >= cutoff]
    events.reverse()   # recent() daje najnowsze pierwsze — raport chce chronologicznie
    return events


def collect_backup_events(period_seconds: float,
                          now_ts: Optional[float] = None) -> List[dict]:
    """Zdarzenia backupu (OK/błąd) z dziennika z ostatniego okresu."""
    return _collect_by_source(_BACKUP_SOURCES, period_seconds, now_ts)


def collect_retention_events(period_seconds: float,
                             now_ts: Optional[float] = None) -> List[dict]:
    """Zdarzenia retencji (usunięcia kopii) z ostatniego okresu."""
    return _collect_by_source((RETENTION_SOURCE,), period_seconds, now_ts)


def _sum_removed(retention_events: List[dict]) -> int:
    """Suma usuniętych kopii — z ustrukturyzowanego pola 'extra' (nie z tekstu)."""
    total = 0
    for e in retention_events:
        try:
            total += int((e.get("extra") or {}).get("removed", 0))
        except (TypeError, ValueError):
            pass
    return total


def build_report(events: List[dict], label: str,
                 retention_events: Optional[List[dict]] = None) -> tuple:
    retention_events = retention_events or []
    ok = [e for e in events if e["level"] == "success"]
    fail = [e for e in events if e["level"] == "error"]
    removed_total = _sum_removed(retention_events)
    subject = f"[FortiBackup] Raport {label}: {len(ok)} OK, {len(fail)} nieudanych"
    lines = [f"Raport {label} wykonanych backupów FortiGate.", ""]
    lines.append(f"Backupy zakończone sukcesem: {len(ok)}")
    lines.append(f"Backupy nieudane:           {len(fail)}")
    lines.append(f"Kopie usunięte (retencja):  {removed_total}")
    lines.append("")
    if fail:
        lines.append("── NIEUDANE ─────────────────────────────")
        for e in fail:
            ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(e.get("ts", 0)))
            lines.append(f"  [{ts}] {e['message']}")
        lines.append("")
    if ok:
        lines.append("── UDANE ────────────────────────────────")
        for e in ok:
            ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(e.get("ts", 0)))
            lines.append(f"  [{ts}] {e['message']}")
        lines.append("")
    if retention_events:
        lines.append("── RETENCJA (usunięte kopie) ────────────")
        for e in retention_events:
            ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(e.get("ts", 0)))
            lines.append(f"  [{ts}] {e['message']}")
    if not events and not retention_events:
        lines.append("W tym okresie nie wykonano żadnych backupów.")
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
            try:
                self._maybe_send_report()
            except Exception as e:  # noqa: BLE001
                EVENTLOG.log("error", f"Notifier (raport): {e}", NOTIFY_SOURCE)

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
        endpoint chce od razu wiedzieć, czy się udało). Wysyłamy do WSZYSTKICH
        skonfigurowanych odbiorców (powiadomienia + raport), bo test sprawdza
        po prostu, czy serwer SMTP działa."""
        # unia z zachowaniem kolejności (bez duplikatów)
        recipients = list(dict.fromkeys(cfg.recipients() + cfg.report_recipients()))
        if not recipients:
            raise ValueError("Nie podano żadnego adresu odbiorcy.")
        send_email(cfg, "[FortiBackup] Wiadomość testowa",
                   "To jest testowe powiadomienie z FortiBackup Web.\n"
                   "Jeśli je widzisz, konfiguracja email działa poprawnie.",
                   recipients=recipients)

    def _maybe_send_report(self, now: Optional[datetime] = None) -> None:
        """Raz na okres (daily/weekly) po zaplanowanej godzinie wysyła zbiorczy
        raport backupów. Nie zależy od logowania — czyta tylko dziennik.
        Odporny na restart (nadrabia miniony termin) i na dubel (stan na dysku)."""
        cfg = load_email_config()
        # raport jest NIEZALEŻNY od powiadomień (cfg.enabled) — wystarczy tryb
        # daily/weekly, skonfigurowany serwer i własna lista odbiorców raportu
        if cfg.report not in ("daily", "weekly"):
            return
        if not cfg.host or not cfg.report_recipients():
            return
        now = now or datetime.now()
        hh, mm = _parse_hhmm(cfg.report_time)
        occ = last_scheduled(now, cfg.report, hh, mm, cfg.report_weekday)
        if occ is None:
            return
        occ_ts = occ.timestamp()
        state = _load_report_state()
        if state.get("last_report_sent", 0) >= occ_ts:
            return                                    # raport za ten okres już poszedł
        # po nieudanej próbie nie młóć co tick — odczekaj REPORT_RETRY_SECONDS
        if now.timestamp() - state.get("last_report_attempt", 0) < REPORT_RETRY_SECONDS:
            return
        period = 7 * 86400 if cfg.report == "weekly" else 86400
        label = "tygodniowy" if cfg.report == "weekly" else "dzienny"
        events = collect_backup_events(period, now_ts=now.timestamp())
        retention = collect_retention_events(period, now_ts=now.timestamp())
        subject, body = build_report(events, label, retention)
        state["last_report_attempt"] = now.timestamp()
        _save_report_state(state)
        try:
            send_email(cfg, subject, body, recipients=cfg.report_recipients())
        except Exception as e:  # noqa: BLE001 — źródło notify => bez pętli
            EVENTLOG.log("error", f"Wysyłka raportu email nie powiodła się: {e}",
                         NOTIFY_SOURCE)
            return
        state["last_report_sent"] = now.timestamp()
        _save_report_state(state)
        EVENTLOG.log("info", f"Wysłano raport {label} ({len(events)} zdarzeń backupu).",
                     NOTIFY_SOURCE)

    def send_report_now(self, cfg: EmailConfig) -> int:
        """Natychmiastowy raport."""
        weekly = cfg.report == "weekly"
        period = 7 * 86400 if weekly else 86400
        label = "tygodniowy" if weekly else "dzienny"
        events = collect_backup_events(period)
        retention = collect_retention_events(period)
        subject, body = build_report(events, label, retention)
        send_email(cfg, subject, body, recipients=cfg.report_recipients())
        return len(events)


NOTIFIER = Notifier()
