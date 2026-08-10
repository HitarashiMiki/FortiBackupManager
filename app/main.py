# -*- coding: utf-8 -*-
"""
main.py — FortiBackup Web (FastAPI).

Najważniejsze decyzje (względem pierwszej wersji webowej):

* Sesje SERVER-SIDE — cookie zawiera tylko losowy token, hasło główne żyje
  w pamięci serwera (SessionMiddleware trzyma dane w cookie klienta —
  podpisanym, ale NIEzaszyfrowanym — więc master password w sesji był
  czytelny dla każdego, kto zobaczył cookie).
* Secret podpisujący cookie generowany przy pierwszym starcie do katalogu
  danych, nie hardcodowany w repo.
* Endpointy są zwykłymi `def` (nie `async def`) — FastAPI odpala je
  w threadpoolu. Blokujące paramiko/ftplib w `async def` zatrzymywało
  cały event loop, czyli jeden wolny SFTP wieszał aplikację WSZYSTKIM
  użytkownikom.
* Ścieżki plików z URL-i są walidowane (tylko <base>/backups/) — wcześniej
  dało się pobrać/skasować dowolny plik konta magazynu, z devices.db włącznie.
* /api/devices nie zwraca haseł SSH ani tokenów API do przeglądarki;
  puste pole przy edycji = zachowaj stary sekret.
* /setup po pierwszej konfiguracji wymaga zalogowania — wcześniej każdy
  mógł podmienić serwer magazynu i przekierować backupy do siebie.
* Backupy jako joby z logiem i statusem odpytywanym przez UI — zamiast
  print-a do stdout i zgadywania "pewnie już skończył".
"""

from __future__ import annotations

import os
import platform
import posixpath
import subprocess
import threading
from contextlib import asynccontextmanager
from dataclasses import asdict
from typing import Optional

from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.responses import (HTMLResponse, RedirectResponse, StreamingResponse,
                               PlainTextResponse, JSONResponse)
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.status import HTTP_302_FOUND, HTTP_401_UNAUTHORIZED

from .config import load_settings, save_settings, AppSettings, _obf
from .storage import open_storage, open_db_storage, StorageConfig, StorageError
from .devicedb import (DeviceDB, Device, WrongPasswordError, DeviceDBError,
                       DBTooNewError, DB_FILENAME, FOLDER_COLORS, db_revision)
from .fortigate import run_backup, device_backup_dir, sanitize_name, BACKUP_DIR
from .diff import make_diff_html
from .changes import (changed_flags, detect_and_log, find_backup_dir_for_host,
                      first_seen_map)
from .audit import run_audit
from .retention import apply_retention, RETENTION_MODES
from .security import (SESSIONS, LOGIN_GUARD, get_or_create_secret,
                       safe_backup_path, PathTraversalError,
                       load_security_config, save_security_config, SecurityConfig,
                       validate_whitelist_entry, SMART_MAX_ATTEMPTS,
                       SMART_BASE_MINUTES, SMART_FACTOR, SMART_MAX_MINUTES)
from .jobs import JOBS
from .eventlog import EVENTLOG, LEVELS as EVENTLOG_LEVELS
from .notifier import (NOTIFIER, load_email_config, save_email_config,
                       EmailConfig)
from .version import VERSION_CHECKER, APP_VERSION
from .scheduler import SCHEDULER

def _env_bool(name: str, default: bool = False) -> bool:
    """Odczyt flagi bool ze zmiennej środowiskowej (np. przy `docker run -e`)."""
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


# Cookie sesji tylko po HTTPS, gdy aplikacja stoi za reverse proxy
# z TLS (Caddy/nginx).
HTTPS_ONLY = _env_bool("FORTIBACKUP_HTTPS_ONLY", False)


def _startup_tasks() -> None:
    SCHEDULER.start_once()
    NOTIFIER.start_once()
    EVENTLOG.subscribe(NOTIFIER.queue_event)
    # sprawdzanie dostępności nowej wersji w tle
    VERSION_CHECKER.start_once()
    # ślad restartu na osi czasu — widać, kiedy proces wstał
    EVENTLOG.log("info", "Aplikacja uruchomiona — harmonogram uśpiony.", "system")


@asynccontextmanager
async def lifespan(app: FastAPI):
    _startup_tasks()
    yield


app = FastAPI(title="FortiBackup Web", docs_url=None, redoc_url=None,
              lifespan=lifespan)


@app.exception_handler(RequestValidationError)
async def _form_validation_handler(request: Request, exc: RequestValidationError):
    """Strony z formularzami HTML (/setup, /login) nie mogą odpowiadać
    surowym JSON-em 422 — użytkownik ma dostać stronę z komunikatem.
    Endpointy /api/* zachowują standardową odpowiedź JSON."""
    path = request.url.path
    if path.startswith("/setup"):
        settings = load_settings()
        logged = bool(SESSIONS.get_master_password(request.session.get("token")))
        return templates.TemplateResponse(
            request=request, name="setup.html",
            context={"settings": settings, "configured": bool(settings.host),
                     "logged": logged,
                     "email": load_email_config().to_public(),
                     "error": "Uzupełnij wymagane pola formularza."},
            status_code=400)
    if path == "/login":
        return templates.TemplateResponse(
            request=request, name="login.html",
            context={"error": "Podaj hasło główne.", "first_run": _is_first_run()},
            status_code=400)
    return await request_validation_exception_handler(request, exc)


@app.exception_handler(StorageError)
def _storage_error_handler(request: Request, exc: StorageError):
    # Problemy z magazynem (złe hasło, host nieosiągalny) nie mogą kończyć
    # się nagim 500 bez treści — UI dostaje komunikat do dziennika zdarzeń.
    return JSONResponse(status_code=502, content={"detail": f"Magazyn: {exc}"})


@app.exception_handler(DBTooNewError)
def _db_too_new_handler(request: Request, exc: DBTooNewError):
    # 426 Upgrade Required — jeden punkt obsługi dla WSZYSTKICH endpointów
    # API: baza zapisana przez nowszą wersję programu, potrzebny update.
    return JSONResponse(status_code=426, content={"detail": str(exc)})


app.add_middleware(
    SessionMiddleware,
    secret_key=get_or_create_secret(),
    max_age=8 * 3600,
    same_site="lax",
    https_only=HTTPS_ONLY,     # FORTIBACKUP_HTTPS_ONLY=true za TLS-em (reverse proxy)
)

templates = Jinja2Templates(directory="app/templates")

_DEVICE_PUBLIC_FIELDS = ("name", "host", "port", "username", "method",
                         "api_port", "vdom_enabled", "description", "folder",
                         "sched_enabled", "sched_mode", "sched_every_hours",
                         "sched_time", "sched_weekday",
                         "retention_mode", "retention_count", "retention_days",
                         "gfs_daily", "gfs_weekly", "gfs_monthly")


def _human_duration(seconds: int) -> str:
    """Czas po polsku, bez sekundowej precyzji tam, gdzie nikogo nie obchodzi."""
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} s"
    minutes = (seconds + 59) // 60
    if minutes < 60:
        return f"{minutes} min"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.0f} h" if hours == int(hours) else f"{hours:.1f} h"
    return f"{hours / 24:.1f} dnia".replace(".0 ", " ")


def _device_public(d: Device) -> dict:
    out = {k: getattr(d, k) for k in _DEVICE_PUBLIC_FIELDS}
    out["has_password"] = bool(d.password)
    out["has_api_token"] = bool(d.api_token)
    return out


# ======================== DEPENDENCIES ========================

def get_master_password(request: Request) -> str:
    mp = SESSIONS.get_master_password(request.session.get("token"))
    if not mp:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Niezalogowany")
    return mp


def get_storage_config() -> StorageConfig:
    settings = load_settings()
    if not settings.host:
        raise HTTPException(status_code=400, detail="Magazyn kopi nie jest skonfigurowany")
    return settings.to_storage_config()


def _load_db(st, mp: str) -> DeviceDB:
    db = DeviceDB(st, mp)
    db.load_or_create()
    return db


def _is_first_run() -> bool:
    """Czy baza urządzeń jeszcze nie istnieje? Wtedy hasło podane przy
    logowaniu dopiero JĄ TWORZY — ekran logowania musi to jasno mówić
    (inaczej 'Odblokuj aplikację' myli: nie ma czego odblokowywać)."""
    try:
        with open_db_storage() as dbst:
            return not dbst.exists(dbst.join(DB_FILENAME))
    except Exception:  # noqa: BLE001 — przy wątpliwości zachowaj się jak zwykłe logowanie
        return False


def _migrate_db_from_remote(settings: AppSettings, dbst, local_path: str) -> None:
    """Jednorazowa migracja: baza urządzeń była kiedyś dostępna na sftp"""
    try:
        with open_storage(settings.to_storage_config()) as rst:
            remote_path = rst.join(DB_FILENAME)
            if rst.exists(remote_path):
                dbst.upload_bytes(rst.download_bytes(remote_path), local_path)
    except StorageError as e:
        raise DeviceDBError(
            f"Brak lokalnej bazy w /DB, a migracja z magazynu nie powiodła się: {e}")



# ======================== AUTH + SETUP ========================

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    settings = load_settings()
    if not settings.host:
        return RedirectResponse("/setup", status_code=HTTP_302_FOUND)
    return templates.TemplateResponse(request=request, name="login.html",
                                      context={"error": None,
                                               "first_run": _is_first_run()})


@app.post("/login")
def login(request: Request, master_password: str = Form(...),
          confirm_master_password: str = Form("")):
    settings = load_settings()
    if not settings.host:
        return RedirectResponse("/setup", status_code=HTTP_302_FOUND)

    first_run = _is_first_run()

    client_ip = request.client.host if request.client else "?"
    blocked_for = LOGIN_GUARD.check(client_ip)
    if blocked_for:
        return templates.TemplateResponse(
            request=request, name="login.html",
            context={"error": "Zbyt dużo nieudanych prób z tego adresu — "
                              f"blokada jeszcze przez {_human_duration(blocked_for)}.",
                     "first_run": first_run},
            status_code=429)

    seccfg = load_security_config()
    if first_run:
        # Pierwsze logowanie TWORZY zaszyfrowaną bazę — dowolne hasło zostanie
        # przyjęte, więc literówka dałaby bazę z hasłem, którego nikt nie zna
        # (nie da się go odzyskać). Stąd wymagane potwierdzenie.
        if len(master_password) < seccfg.min_master_password_length:
            return templates.TemplateResponse(
                request=request, name="login.html",
                context={"error": "Hasło główne musi mieć co najmniej "
                                  f"{seccfg.min_master_password_length} znaków.",
                         "first_run": True})
        if confirm_master_password != master_password:
            return templates.TemplateResponse(
                request=request, name="login.html",
                context={"error": "Hasła nie są identyczne — spróbuj ponownie.",
                         "first_run": True})

    try:
        with open_db_storage() as dbst:
            local_path = dbst.join(DB_FILENAME)
            if not dbst.exists(local_path):
                _migrate_db_from_remote(settings, dbst, local_path)
            _load_db(dbst, master_password)
    except WrongPasswordError:
        # Tylko BŁĘDNE HASŁO liczy się do blokady. Błąd magazynu czy zbyt nowa
        # baza to nie jest próba włamania — banowanie za nie odcinałoby admina
        # od aplikacji dokładnie wtedy, gdy musi ją naprawić.
        banned_for = LOGIN_GUARD.record_failure(client_ip)
        if seccfg.log_login_attempts:
            EVENTLOG.log("warning",
                         f"Nieudane logowanie z {client_ip}" +
                         (f" — blokada na {_human_duration(banned_for)}." if banned_for else "."),
                         "security")
        if banned_for:
            return templates.TemplateResponse(
                request=request, name="login.html",
                context={"error": "Zbyt dużo nieudanych prób — adres zablokowany na "
                                  f"{_human_duration(banned_for)}.",
                         "first_run": False},
                status_code=429)
        return templates.TemplateResponse(
            request=request, name="login.html",
            context={"error": "Błędne hasło bazy danych", "first_run": False})
    except DBTooNewError as e:
        # Drugie (obok API/426) miejsce powiadomienia: już przy logowaniu,
        # zanim ktokolwiek zdąży cokolwiek zapisać do bazy.
        return templates.TemplateResponse(
            request=request, name="login.html",
            context={"error": str(e), "first_run": False})
    except DeviceDBError as e:
        return templates.TemplateResponse(
            request=request, name="login.html",
            context={"error": str(e), "first_run": first_run})
    except Exception as e:
        return templates.TemplateResponse(
            request=request, name="login.html",
            context={"error": f"Błąd połączenia: {e}", "first_run": first_run})

    LOGIN_GUARD.record_success(client_ip)
    if seccfg.log_login_attempts:
        EVENTLOG.log("info", f"Zalogowano z {client_ip}.", "security")
    # W cookie ląduje wyłącznie losowy token; hasło zostaje w RAM serwera.
    request.session["token"] = SESSIONS.create(master_password)
    # Każde udane logowanie uzbraja/odświeża harmonogram automatycznych
    # backupów (serwer nie trzyma hasła głównego na dysku, więc po
    # restarcie scheduler śpi do pierwszego logowania).
    SCHEDULER.arm(master_password)
    return RedirectResponse("/", status_code=HTTP_302_FOUND)


@app.get("/logout")
def logout(request: Request):
    SESSIONS.destroy(request.session.get("token"))
    request.session.clear()
    return RedirectResponse("/login", status_code=HTTP_302_FOUND)


def _setup_authorized(request: Request, confirm_password: str = "") -> bool:
    """Dostęp do zmiany/resetu konfiguracji:
    (a) aktywna sesja, ALBO
    (b) znajomość AKTUALNEGO hasła magazynu".
    """
    if SESSIONS.get_master_password(request.session.get("token")):
        return True
    settings = load_settings()
    if not settings.host:
        return True
    if not confirm_password:
        return False
    client_ip = request.client.host if request.client else "?"
    if LOGIN_GUARD.check(client_ip):
        return False
    ok = confirm_password == settings.to_storage_config().password
    if not ok:
        # Ta ścieżka też jest zgadywaniem hasła — musi wchodzić do tej samej
        # puli prób co /login, inaczej blokada logowania jest do obejścia.
        LOGIN_GUARD.record_failure(client_ip)
    return ok


@app.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request):
    settings = load_settings()
    logged = bool(SESSIONS.get_master_password(request.session.get("token")))
    return templates.TemplateResponse(
        request=request, name="setup.html",
        context={"settings": settings,
                 "configured": bool(settings.host),
                 "logged": logged,
                 "email": load_email_config().to_public(),
                 "error": None})


@app.post("/setup")
def save_setup(
    request: Request,
    protocol: str = Form(...),
    host: str = Form(...),
    port: int = Form(...),
    username: str = Form(...),
    password: str = Form(""),      # puste przy edycji = zachowaj stare hasło
    base_path: str = Form("/fortibackup"),
    confirm_password: str = Form(""),
):
    old = load_settings()
    if not _setup_authorized(request, confirm_password):
        return templates.TemplateResponse(
            request=request, name="setup.html",
            context={"settings": old, "configured": True,
                     "logged": False,
                     "error": "Błędne hasło magazynu kopi (albo limit prób — odczekaj minutę)."})
    if not password and not old.password_obf:
        # świeża instalacja — nie ma starego hasła, które można zachować
        return templates.TemplateResponse(
            request=request, name="setup.html",
            context={"settings": old, "configured": bool(old.host),
                     "logged": True,
                     "error": "Podaj hasło do serwera magazynu."})
    settings = AppSettings(
        protocol=protocol,
        host=host.strip(),
        port=port,
        username=username.strip(),
        # puste pole = bez zmian (ta sama konwencja co przy sekretach urządzeń)
        password_obf=_obf(password) if password else old.password_obf,
        base_path=base_path.strip() or "/fortibackup",
    )
    # Test połączenia PRZED zapisem — złe hasło/host ma wyskoczyć tutaj,
    # z czytelnym komunikatem, a nie dopiero przy pierwszym backupie.
    # ensure_dir łapie też pułapkę chroota (korzeń read-only).
    try:
        cfg = settings.to_storage_config()
        with open_storage(cfg) as st:
            st.ensure_dir(cfg.base_path)
    except StorageError as e:
        logged = bool(SESSIONS.get_master_password(request.session.get("token")))
        return templates.TemplateResponse(
            request=request, name="setup.html",
            context={"settings": settings, "configured": bool(old.host),
                     "logged": logged,
                     "email": load_email_config().to_public(),
                     "error": f"Połączenie z magazynem nie powiodło się — nic nie zapisano. {e}"})
    save_settings(settings)
    SCHEDULER.refresh()
    return RedirectResponse("/login", status_code=HTTP_302_FOUND)


@app.post("/setup/reset")
def reset_setup(request: Request, confirm_password: str = Form("")):
    """Wyczyszczenie konfiguracji magazynu."""
    if not _setup_authorized(request, confirm_password):
        settings = load_settings()
        return templates.TemplateResponse(
            request=request, name="setup.html",
            context={"settings": settings, "configured": True,
                     "logged": False,
                     "error": "Błędne hasło bazy danych (albo limit prób — odczekaj minutę)."})
    save_settings(AppSettings())      # pusta konfiguracja
    SCHEDULER.disarm()
    request.session.clear()
    return RedirectResponse("/setup", status_code=HTTP_302_FOUND)


# ======================== POWIADOMIENIA EMAIL ========================

def _email_from_form(enabled, host, port, username, password, use_ssl,
                     use_starttls, from_addr, to_addrs, min_level,
                     report="off", report_time="08:00", report_weekday=0,
                     report_to_addrs="") -> EmailConfig:
    old = load_email_config()
    return EmailConfig(
        enabled=enabled, host=host.strip(), port=port,
        username=username.strip(),
        # puste pole hasła = zachowaj dotychczasowe (jak przy magazynie/urządzeniach)
        password_obf=_obf(password) if password else old.password_obf,
        use_ssl=use_ssl, use_starttls=use_starttls,
        from_addr=from_addr.strip(),
        to_addrs=to_addrs.strip(),            # odbiorcy powiadomień
        min_level=min_level if min_level in ("warning", "error") else "warning",
        report=report if report in ("off", "daily", "weekly") else "off",
        report_time=report_time.strip() or "08:00",
        report_weekday=report_weekday,
        report_to_addrs=report_to_addrs.strip(),   # odbiorcy raportu (osobno)
    )


@app.get("/api/email")
def get_email_config(mp: str = Depends(get_master_password)):
    return load_email_config().to_public()


@app.post("/api/email")
def save_email(
    enabled: bool = Form(False),
    host: str = Form(""),
    port: int = Form(587),
    username: str = Form(""),
    password: str = Form(""),
    use_ssl: bool = Form(False),
    use_starttls: bool = Form(True),
    from_addr: str = Form(""),
    to_addrs: str = Form(""),
    min_level: str = Form("warning"),
    report: str = Form("off"),
    report_time: str = Form("08:00"),
    report_weekday: int = Form(0),
    report_to_addrs: str = Form(""),
    mp: str = Depends(get_master_password),
):
    cfg = _email_from_form(enabled, host, port, username, password, use_ssl,
                           use_starttls, from_addr, to_addrs, min_level,
                           report, report_time, report_weekday, report_to_addrs)
    # każda włączona funkcja wymaga SWOICH odbiorców (listy są niezależne)
    if cfg.enabled and not cfg.recipients():
        raise HTTPException(status_code=400,
                            detail="Włączono powiadomienia, ale nie podano odbiorców powiadomień.")
    if cfg.report != "off" and not cfg.report_recipients():
        raise HTTPException(status_code=400,
                            detail="Włączono raport, ale nie podano odbiorców raportu.")
    save_email_config(cfg)
    return {"status": "ok", "message": "Zapisano konfigurację powiadomień email."}


@app.post("/api/email/test")
def test_email(
    enabled: bool = Form(False),
    host: str = Form(""),
    port: int = Form(587),
    username: str = Form(""),
    password: str = Form(""),
    use_ssl: bool = Form(False),
    use_starttls: bool = Form(True),
    from_addr: str = Form(""),
    to_addrs: str = Form(""),
    min_level: str = Form("warning"),
    report: str = Form("off"),
    report_time: str = Form("08:00"),
    report_weekday: int = Form(0),
    report_to_addrs: str = Form(""),
    mp: str = Depends(get_master_password),
):
    """Wysyła testowy mail z DANYCH Z FORMULARZA, żeby dało
    się sprawdzić ustawienia przed zapisaniem. Puste hasło = użyj zapisanego."""
    cfg = _email_from_form(enabled, host, port, username, password, use_ssl,
                           use_starttls, from_addr, to_addrs, min_level,
                           report, report_time, report_weekday, report_to_addrs)
    try:
        NOTIFIER.send_test(cfg)
    except Exception as e:  # noqa: BLE001 — pokaż użytkownikowi przyczynę
        raise HTTPException(status_code=400, detail=f"Wysyłka powiadomienia nie powiodła się: {e}")
    recipients = list(dict.fromkeys(cfg.recipients() + cfg.report_recipients()))
    return {"status": "ok", "message": f"Wysłano wiadomość testową do: {', '.join(recipients)}"}


@app.post("/api/email/report-now")
def report_now(
    enabled: bool = Form(False),
    host: str = Form(""),
    port: int = Form(587),
    username: str = Form(""),
    password: str = Form(""),
    use_ssl: bool = Form(False),
    use_starttls: bool = Form(True),
    from_addr: str = Form(""),
    to_addrs: str = Form(""),
    min_level: str = Form("warning"),
    report: str = Form("daily"),
    report_time: str = Form("08:00"),
    report_weekday: int = Form(0),
    report_to_addrs: str = Form(""),
    mp: str = Depends(get_master_password),
):
    """Natychmiastowy raport, cotygodniowy lub codzienny"""
    cfg = _email_from_form(enabled, host, port, username, password, use_ssl,
                           use_starttls, from_addr, to_addrs, min_level,
                           report if report != "off" else "daily",
                           report_time, report_weekday, report_to_addrs)
    try:
        n = NOTIFIER.send_report_now(cfg)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Wysyłka raportu nie powiodła się: {e}")
    return {"status": "ok", "message": f"Wysłano raport ({n} zdarzeń) do: {', '.join(cfg.report_recipients())}"}


# ======================== MAIN PAGE ========================

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    if not SESSIONS.get_master_password(request.session.get("token")):
        return RedirectResponse("/login", status_code=HTTP_302_FOUND)
    settings = load_settings()
    summary = settings.to_storage_config().summary() if settings.host else "Brak konfiguracji"
    return templates.TemplateResponse(request=request, name="index.html",
                                      context={"settings_summary": summary})


# ======================== DEVICES ========================

@app.get("/api/devices")
def list_devices(mp: str = Depends(get_master_password)):
    with open_db_storage() as st:
        db = _load_db(st, mp)
        return {"devices": [_device_public(d) for d in db.devices],
                "folders": db.folders,
                "folder_colors": db.folder_colors,
                "palette": list(FOLDER_COLORS)}


def _validate_folder(db: DeviceDB, folder: str) -> str:
    folder = folder.strip()
    if folder and folder not in db.folders:
        raise HTTPException(status_code=400, detail=f"Folder '{folder}' nie istnieje")
    return folder


@app.post("/api/devices")
def add_device(
    name: str = Form(...),
    host: str = Form(...),
    port: int = Form(22),
    username: str = Form("admin"),
    password: str = Form(""),
    method: str = Form("ssh_push"),
    api_token: str = Form(""),
    api_port: int = Form(443),
    vdom_enabled: bool = Form(False),
    description: str = Form(""),
    folder: str = Form(""),
    sched_enabled: bool = Form(False),
    sched_mode: str = Form("daily"),
    sched_every_hours: int = Form(24),
    sched_time: str = Form("02:00"),
    sched_weekday: int = Form(0),
    mp: str = Depends(get_master_password),
):
    with open_db_storage() as st:
        db = _load_db(st, mp)
        device = Device(
            name=name.strip(), host=host.strip(), port=port,
            username=username.strip(), password=password, method=method,
            api_token=api_token.strip(), api_port=api_port,
            vdom_enabled=vdom_enabled, description=description.strip(),
            folder=_validate_folder(db, folder),
            sched_enabled=sched_enabled, sched_mode=sched_mode,
            sched_every_hours=sched_every_hours, sched_time=sched_time.strip(),
            sched_weekday=sched_weekday,
        )
        # DODANIE musi odrzucić istniejącą nazwę.
        def _insert(d: DeviceDB):
            if d.get(device.name):
                raise HTTPException(
                    status_code=400,
                    detail=f"Urządzenie o nazwie '{device.name}' już istnieje.")
            d.devices.append(device)
            d.devices.sort(key=lambda x: x.name.lower())
            d.save()

        try:
            db.mutate(_insert)
        except DeviceDBError as e:
            raise HTTPException(status_code=400, detail=str(e))
        SCHEDULER.refresh()
        message = f"Dodano urządzenie: {device.name}"
        # Best-effort: jeśli na magazynie leżą osierocone backupy tego hosta
        # (odtwarzanie po utracie bazy urządzeń), przypnij je. Błąd magazynu
        # nie może zablokować dodania urządzenia.
        try:
            attached = _attach_orphan_backups(db, device)
            if attached:
                message += " " + attached
        except Exception:  # noqa: BLE001
            pass
        EVENTLOG.log("info", f"Dodano urządzenie: {device.name} ({device.host})", "inwentarz")
        return {"status": "ok", "message": message}


def _attach_orphan_backups(db: DeviceDB, device: Device) -> str:
    """Dopasowanie backupów przy (ponownym) dodaniu urządzenia.

    1) Katalog o pasującej nazwie z plikami -> nic nie trzeba robić,
       działa dotychczasowe dopasowanie po nazwie (raportujemy znalezisko).
    2) Inaczej: szukamy katalogu, którego .fbk-meta.json wskazuje ten sam
       host — nazwy urządzeń po odtworzeniu bazy nikt nie pamięta, adresy są
       w dokumentacji sieci. Trafienie przypinamy przez Device.backup_dir."""
    settings = load_settings()
    if not settings.host:
        return ""
    with open_storage(settings.to_storage_config()) as rst:
        own_dir = device_backup_dir(rst, device)
        own = [f for f in rst.list_files(own_dir) if not f.name.startswith(".")]
        if own:
            return f"Znaleziono istniejące backupy o tej nazwie ({len(own)} wersji)."
        root = rst.join(BACKUP_DIR)
        claimed = {sanitize_name(d.backup_dir or d.name)
                   for d in db.devices if d.name != device.name}
        found = find_backup_dir_for_host(rst, root, device.host, claimed)
        if not found:
            return ""
        count = len([f for f in rst.list_files(posixpath.join(root, found))
                     if not f.name.startswith(".")])
    device.backup_dir = found
    db.upsert(device, old_name=device.name)
    return (f"Dopasowano istniejące backupy po adresie {device.host} "
            f"(katalog '{found}', {count} wersji).")


@app.get("/api/devices/{name}")
def get_device(name: str, mp: str = Depends(get_master_password)):
    with open_db_storage() as st:
        db = _load_db(st, mp)
        device = db.get(name)
        if not device:
            raise HTTPException(status_code=404, detail="Urządzenie nie istnieje")
        return _device_public(device)


@app.put("/api/devices/{name}")
def update_device(
    name: str,
    new_name: str = Form(...),
    host: str = Form(...),
    port: int = Form(22),
    username: str = Form("admin"),
    password: str = Form(""),
    method: str = Form("ssh_push"),
    api_token: str = Form(""),
    api_port: int = Form(443),
    vdom_enabled: bool = Form(False),
    description: str = Form(""),
    folder: str = Form(""),
    sched_enabled: bool = Form(False),
    sched_mode: str = Form("daily"),
    sched_every_hours: int = Form(24),
    sched_time: str = Form("02:00"),
    sched_weekday: int = Form(0),
    mp: str = Depends(get_master_password),
):
    with open_db_storage() as st:
        db = _load_db(st, mp)
        old = db.get(name)
        if not old:
            raise HTTPException(status_code=404, detail="Urządzenie nie istnieje")
        device = Device(
            name=new_name.strip(), host=host.strip(), port=port,
            username=username.strip(),
            password=password or old.password,          # puste = bez zmian
            method=method,
            api_token=api_token.strip() or old.api_token,  # puste = bez zmian
            api_port=api_port, vdom_enabled=vdom_enabled,
            description=description.strip(),
            folder=_validate_folder(db, folder),
            extra=old.extra,
            # zmiana nazwy nie może gubić historii: dotychczasowy
            # katalog backupów (jawny, a gdy go nie było — pochodną starej nazwy)
            backup_dir=(old.backup_dir if new_name.strip() == old.name
                        else old.backup_dir or sanitize_name(old.name)),
            # retencja ma osobny formularz (modal) — edycja urządzenia jej nie tyka
            retention_mode=old.retention_mode, retention_count=old.retention_count,
            retention_days=old.retention_days, gfs_daily=old.gfs_daily,
            gfs_weekly=old.gfs_weekly, gfs_monthly=old.gfs_monthly,
            sched_enabled=sched_enabled, sched_mode=sched_mode,
            sched_every_hours=sched_every_hours, sched_time=sched_time.strip(),
            sched_weekday=sched_weekday,
        )
        try:
            db.upsert(device, old_name=name)
            SCHEDULER.refresh()
        except DeviceDBError as e:
            raise HTTPException(status_code=400, detail=str(e))
        if new_name.strip() != name:
            EVENTLOG.log("info", f"Zmieniono nazwę urządzenia: {name} → {new_name.strip()}", "inwentarz")
        else:
            EVENTLOG.log("info", f"Zaktualizowano urządzenie: {new_name.strip()}", "inwentarz")
        return {"status": "ok", "message": "Urządzenie zaktualizowane"}


@app.delete("/api/devices/{name}")
def delete_device(name: str, mp: str = Depends(get_master_password)):
    """Usuwa urządzenie z bazy. Backupy na magazynie zostają nietknięte."""
    with open_db_storage() as st:
        db = _load_db(st, mp)
        db.remove(name)
        SCHEDULER.refresh()
        EVENTLOG.log("info", f"Usunięto urządzenie: {name} z bazy", "inwentarz")
        return {"status": "ok", "message": f"Usunięto urządzenie: {name}"}


@app.post("/api/devices/{name}/move")
def move_device(name: str, folder: str = Form(""),
                mp: str = Depends(get_master_password)):
    with open_db_storage() as st:
        db = _load_db(st, mp)
        try:
            db.move_device(name, folder)
        except DeviceDBError as e:
            raise HTTPException(status_code=400, detail=str(e))
        target = folder.strip() or "poza foldery"
        EVENTLOG.log("info", f"Przeniesiono urządzenie '{name}' → {target}", "inwentarz")
        return {"status": "ok", "message": f"Przeniesiono '{name}' → {target}"}


# ======================== RETENCJA ========================

@app.post("/api/devices/{name}/retention")
def save_retention(
    name: str,
    retention_mode: str = Form("off"),
    retention_count: int = Form(30),
    retention_days: int = Form(90),
    gfs_daily: int = Form(7),
    gfs_weekly: int = Form(4),
    gfs_monthly: int = Form(12),
    mp: str = Depends(get_master_password),
):
    if retention_mode not in RETENTION_MODES:
        raise HTTPException(status_code=400, detail="Nieznany tryb retencji.")
    with open_db_storage() as st:
        db = _load_db(st, mp)

        # Zmiana kilku pól ISTNIEJĄCEGO urządzenia musi iść na świeżym stanie
        # pod lockiem — inaczej zapis retencji cofnąłby edycję urządzenia,
        # którą ktoś inny zrobił sekundę wcześniej
        def _apply(d: DeviceDB):
            device = d.get(name)
            if not device:
                raise HTTPException(status_code=404, detail="Urządzenie nie istnieje")
            # liczniki nieujemne; count/gfs-daily min. 1, by nie skasować wszystkiego
            device.retention_mode = retention_mode
            device.retention_count = max(1, retention_count)
            device.retention_days = max(1, retention_days)
            device.gfs_daily = max(0, gfs_daily)
            device.gfs_weekly = max(0, gfs_weekly)
            device.gfs_monthly = max(0, gfs_monthly)
            d.save()

        db.mutate(_apply)
        return {"status": "ok", "message": "Zapisano ustawienia retencji."}


def _run_retention_job(job, cfg: StorageConfig, mp: str, device_name: str):
    """Wątek roboczy: ręczne zastosowanie retencji (usuwanie z magazynu)."""
    ok = True
    try:
        with open_db_storage() as dbst:
            device = _load_db(dbst, mp).get(device_name)
        if not device:
            JOBS.log(job, "Urządzenie nie istnieje.")
            ok = False
        elif device.retention_mode == "off":
            JOBS.log(job, "Retencja wyłączona — nic nie usuwam.")
        else:
            with open_storage(cfg) as st:
                removed = apply_retention(device, st, logger=lambda m: JOBS.log(job, m))
                JOBS.log(job, f"Zakończono. Usunięto {removed} kopii.")
                job.ok_count += 1
    except Exception as e:  # noqa: BLE001
        JOBS.log(job, f"BŁĄD: {e}")
        ok = False
    JOBS.finish(job, ok)


@app.post("/api/devices/{name}/retention/apply")
def apply_retention_now(name: str, mp: str = Depends(get_master_password)):
    """Zastosuj retencję teraz (bez czekania na kolejny backup). Usuwanie
    z magazynu leci jako job w tle — UI polluje wynik jak przy backupie."""
    cfg = get_storage_config()
    job = JOBS.create(f"Retencja: {name}")
    JOBS.log(job, f"Zastosowanie retencji dla {name}")
    threading.Thread(target=_run_retention_job, args=(job, cfg, mp, name),
                     daemon=True).start()
    return {"status": "started", "job_id": job.id}


# ======================== FOLDERY ========================

@app.post("/api/folders")
def add_folder(name: str = Form(...), color: str = Form(""),
               mp: str = Depends(get_master_password)):
    # baza urządzeń żyje lokalnie w /DB (open_db_storage), nie na magazynie
    with open_db_storage() as st:
        db = _load_db(st, mp)
        try:
            db.add_folder(name, color)
        except DeviceDBError as e:
            raise HTTPException(status_code=400, detail=str(e))
        EVENTLOG.log("info", f"Utworzono folder: {name.strip()}", "inwentarz")
        return {"status": "ok", "message": f"Utworzono folder: {name.strip()}"}


@app.post("/api/folders/{name}/color")
def set_folder_color(name: str, color: str = Form(""),
                     mp: str = Depends(get_master_password)):
    """Zmiana koloru folderu. Pusty/nieznany kolor = powrót do domyślnego."""
    with open_db_storage() as st:
        db = _load_db(st, mp)
        try:
            db.set_folder_color(name, color)
        except DeviceDBError as e:
            raise HTTPException(status_code=400, detail=str(e))
        return {"status": "ok"}


@app.delete("/api/folders/{name}")
def delete_folder(name: str, mp: str = Depends(get_master_password)):
    """Usuwa folder; urządzenia z niego zostaną przeniesione poza folder."""
    with open_db_storage() as st:
        db = _load_db(st, mp)
        try:
            moved = db.remove_folder(name)
        except DeviceDBError as e:
            raise HTTPException(status_code=400, detail=str(e))
        EVENTLOG.log("info", f"Usunięto folder '{name}' ({moved})", "inwentarz")
        return {"status": "ok",
                "message": f"Usunięto folder '{name}' ({moved} urz. przeniesionych poza foldery)"}


# ======================== SCHEDULER ========================

@app.get("/api/scheduler")
def scheduler_status(mp: str = Depends(get_master_password)):
    return SCHEDULER.status()


# ======================== BACKUP (JOBY) ========================

def _run_backup_job(job, cfg: StorageConfig, mp: str, device_names: Optional[list]):
    """Wątek roboczy: backup jednego lub wszystkich urządzeń, log do joba."""
    ok = True
    try:
        with open_db_storage() as dbst:
            db = _load_db(dbst, mp)
        with open_storage(cfg) as st:
            targets = ([d for d in db.devices if d.name in device_names]
                       if device_names else list(db.devices))
            if not targets:
                JOBS.log(job, "Brak urządzeń do backupu.")
                ok = False
            for dev in targets:
                try:
                    path = run_backup(dev, st, logger=lambda m: JOBS.log(job, m))
                    JOBS.log(job, f"[{dev.name}] OK → {path}")
                    detect_and_log(st, device_backup_dir(st, dev), path,
                                   lambda m, n=dev.name: JOBS.log(job, f"[{n}] {m}"),
                                   device=dev)
                    job.ok_count += 1
                    EVENTLOG.log("success", f"Backup OK: {dev.name} → {path}", "backup")
                    # przytnij stare kopie wg retencji (best-effort — błąd
                    # retencji nie może unieważnić udanego backupu)
                    try:
                        apply_retention(dev, st, logger=lambda m, n=dev.name: JOBS.log(job, f"[{n}] {m}"))
                    except Exception as e:  # noqa: BLE001
                        JOBS.log(job, f"[{dev.name}] Retencja pominięta: {e}")
                except Exception as e:  # noqa: BLE001
                    JOBS.log(job, f"[{dev.name}] BŁĄD: {e}")
                    job.fail_count += 1
                    ok = False
                    EVENTLOG.log("error", f"Backup NIEUDANY: {dev.name} — {e}", "backup")
    except Exception as e:  # noqa: BLE001
        JOBS.log(job, f"BŁĄD: {e}")
        ok = False
        EVENTLOG.log("error", f"Backup przerwany: {e}", "backup")
    JOBS.finish(job, ok)


@app.post("/api/backup/{device_name}")
def backup_device(device_name: str, mp: str = Depends(get_master_password)):
    cfg = get_storage_config()
    job = JOBS.create(f"Backup: {device_name}")
    JOBS.log(job, f"Start backupu urządzenia {device_name}")
    threading.Thread(target=_run_backup_job, args=(job, cfg, mp, [device_name]),
                     daemon=True).start()
    return {"status": "started", "job_id": job.id}


@app.post("/api/backup-all")
def backup_all(mp: str = Depends(get_master_password)):
    cfg = get_storage_config()
    job = JOBS.create("Backup wszystkich urządzeń")
    JOBS.log(job, "Start backupu wszystkich urządzeń")
    threading.Thread(target=_run_backup_job, args=(job, cfg, mp, None),
                     daemon=True).start()
    return {"status": "started", "job_id": job.id}


# ======================== (PING / TRACEROUTE) ========================

NET_TOOL_TIMEOUT = 90


def _ping_cmd(host: str) -> list:
    if platform.system() == "Windows":
        return ["ping", "-n", "4", host]
    # -W 2: nie czekaj w nieskończoność na odpowiedź martwego hosta
    return ["ping", "-c", "4", "-W", "2", host]


def _traceroute_cmd(host: str) -> list:
    if platform.system() == "Windows":
        return ["tracert", "-d", "-w", "2000", host]
    # -n: bez reverse-DNS (bywa wolniejszy niż sam pomiar), -q 1: 1 sonda/hop
    return ["traceroute", "-n", "-w", "2", "-q", "1", host]


def _run_net_tool_job(job, cmd: list, tool_name: str) -> None:
    """Wątek roboczy: uruchamia narzędzie sieciowe i streamuje output
    linia po linii do logu joba (UI polluje /api/jobs/{id})."""
    ok = True
    proc = None
    try:
        JOBS.log(job, "$ " + " ".join(cmd))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                text=True, errors="replace")
        watchdog = threading.Timer(NET_TOOL_TIMEOUT, proc.kill)
        watchdog.start()
        try:
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    JOBS.log(job, line)
            rc = proc.wait()
        finally:
            timed_out = not watchdog.is_alive()
            watchdog.cancel()
        if timed_out:
            JOBS.log(job, f"{tool_name}: przerwano po {NET_TOOL_TIMEOUT} s (timeout)")
            ok = False
        elif rc != 0:
            JOBS.log(job, f"{tool_name}: zakończone kodem {rc}")
            ok = False
    except FileNotFoundError:
        JOBS.log(job, f"Polecenie '{cmd[0]}' nie jest dostępne w tym środowisku "
                      f"(w kontenerze wymaga pakietów iputils-ping / traceroute — "
                      f"przebuduj obraz z aktualnego Dockerfile).")
        ok = False
    except Exception as e:  # noqa: BLE001
        JOBS.log(job, f"BŁĄD: {e}")
        ok = False
    finally:
        if proc and proc.poll() is None:
            proc.kill()
    if ok:
        job.ok_count += 1
    else:
        job.fail_count += 1
    JOBS.finish(job, ok)


def _start_net_tool(device_name: str, mp: str, tool: str):
    """Wspólny start dla ping/traceroute: host bierzemy z bazy urządzeń
    (nie z parametru przeglądarki) — brak możliwości odpalenia narzędzia
    na dowolnym adresie spoza bazy."""
    with open_db_storage() as st:
        db = _load_db(st, mp)
        device = db.get(device_name)
    if not device:
        raise HTTPException(status_code=404, detail="Urządzenie nie istnieje")
    if tool == "ping":
        cmd, label = _ping_cmd(device.host), "Ping"
    else:
        cmd, label = _traceroute_cmd(device.host), "Traceroute"
    job = JOBS.create(f"{label}: {device_name}")
    JOBS.log(job, f"{label} do {device_name} ({device.host})")
    threading.Thread(target=_run_net_tool_job, args=(job, cmd, label),
                     daemon=True).start()
    return {"status": "started", "job_id": job.id}


@app.post("/api/ping/{device_name}")
def ping_device(device_name: str, mp: str = Depends(get_master_password)):
    return _start_net_tool(device_name, mp, "ping")


@app.post("/api/traceroute/{device_name}")
def traceroute_device(device_name: str, mp: str = Depends(get_master_password)):
    return _start_net_tool(device_name, mp, "traceroute")


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str, mp: str = Depends(get_master_password)):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Nieznane zadanie")
    return job.to_dict()


@app.get("/api/jobs")
def jobs_recent(mp: str = Depends(get_master_password)):
    return {"jobs": [j.to_dict() for j in JOBS.recent()]}


# ======================== GLOBALNY DZIENNIK ========================

@app.get("/api/eventlog")
def eventlog_recent(level: str = "", limit: int = 200,
                    mp: str = Depends(get_master_password)):
    """Globalny event log."""
    lvl = level if level in EVENTLOG_LEVELS else None
    return {"events": EVENTLOG.recent(limit=limit, level=lvl)}




# ======================== BEZPIECZEŃSTWO ========================

@app.get("/security", response_class=HTMLResponse)
def security_page(request: Request):
    """Osobna strona (nie modal) — ustawienia bezpieczeństwa."""
    if not SESSIONS.get_master_password(request.session.get("token")):
        return RedirectResponse("/login", status_code=HTTP_302_FOUND)
    return templates.TemplateResponse(request=request, name="security.html", context={})


@app.get("/api/security")
def get_security(mp: str = Depends(get_master_password)):
    cfg = load_security_config()
    return {
        "config": asdict(cfg),
        # stałe trybu inteligentnego — UI je pokazuje, ale nie pozwala zmieniać
        "smart": {"max_attempts": SMART_MAX_ATTEMPTS,
                  "base_minutes": SMART_BASE_MINUTES,
                  "factor": SMART_FACTOR,
                  "max_minutes": SMART_MAX_MINUTES},
        "bans": LOGIN_GUARD.active_bans(),
        "offenders": LOGIN_GUARD.recent_offenders(),
    }


@app.post("/api/security")
def save_security(
    max_attempts: int = Form(5),
    window_minutes: int = Form(1),
    ban_minutes: int = Form(15),
    smart_ban: bool = Form(False),
    smart_grace_bans: int = Form(2),
    whitelist: str = Form(""),
    session_ttl_hours: int = Form(8),
    min_master_password_length: int = Form(8),
    log_login_attempts: bool = Form(True),
    verify_device_tls: bool = Form(False),
    mp: str = Depends(get_master_password),
):
    # Whitelist przychodzi jako tekst (jeden wpis na linię lub po przecinku).
    # Walidujemy KAŻDY wpis — zły format cicho przepuszczony oznaczałby, że
    # admin myśli, że ma wyjątek, a go nie ma.
    entries = []
    for raw in whitelist.replace(",", "\n").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            entries.append(validate_whitelist_entry(raw))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    cfg = SecurityConfig(
        max_attempts=max_attempts, window_minutes=window_minutes,
        ban_minutes=ban_minutes, smart_ban=smart_ban,
        smart_grace_bans=smart_grace_bans, whitelist=entries,
        session_ttl_hours=session_ttl_hours,
        min_master_password_length=min_master_password_length,
        log_login_attempts=log_login_attempts,
        verify_device_tls=verify_device_tls,
    )
    save_security_config(cfg)
    EVENTLOG.log("info", "Zmieniono ustawienia bezpieczeństwa.", "security")
    return {"status": "ok", "message": "Zapisano ustawienia bezpieczeństwa.",
            "config": asdict(cfg)}


@app.delete("/api/security/bans/{ip}")
def unban_ip(ip: str, mp: str = Depends(get_master_password)):
    was = LOGIN_GUARD.unban(ip)
    EVENTLOG.log("info", f"Zdjęto blokadę logowania z adresu {ip}.", "security")
    return {"status": "ok", "was_banned": was,
            "message": f"Odblokowano {ip}." if was else f"{ip} nie był zablokowany."}


@app.post("/api/security/bans/reset")
def reset_bans(mp: str = Depends(get_master_password)):
    LOGIN_GUARD.reset()
    EVENTLOG.log("info", "Wyczyszczono wszystkie blokady logowania.", "security")
    return {"status": "ok", "message": "Wyczyszczono blokady."}


# ======================== SYNCHRONIZACJA MIĘDZY UŻYTKOWNIKAMI ========================

@app.get("/api/state")
def app_state(mp: str = Depends(get_master_password)):
    """Lekki "puls" dla przeglądarek.
    """
    return {"devices_rev": db_revision(), "log_seq": EVENTLOG.seq}


# ======================== VERSIONS ========================

@app.get("/api/versions/{device_name}")
def list_versions(device_name: str, mp: str = Depends(get_master_password)):
    cfg = get_storage_config()
    # realne urządzenie z bazy — honoruje przypięty katalog (backup_dir);
    # fallback na nazwę pozwala obejrzeć katalog nieistniejącego już urządzenia
    with open_db_storage() as dbst:
        device = _load_db(dbst, mp).get(device_name)
    device = device or Device(name=device_name, host="")
    with open_storage(cfg) as st:
        path = device_backup_dir(st, device)
        files = [f for f in st.list_files(path) if not f.name.startswith(".")]
        files.sort(key=lambda f: f.name, reverse=True)
        flags = changed_flags(st, path)
        # first_seen: kopia zwinięta przez harmonogram (identyczna treść przez
        # kilka backupów) — nazwa pierwszego pliku z tą treścią
        seen = first_seen_map(st, path)
        return {"versions": [
            {"name": f.name, "path": f.path, "size": f.size,
             "mtime": f.mtime.isoformat() if f.mtime else None,
             "changed": flags.get(f.name),
             "unchanged_since": seen.get(f.name)}
            for f in files
        ]}


def _validated_path(path: str) -> str:
    cfg = get_storage_config()
    try:
        return safe_backup_path(cfg.base_path, path)
    except PathTraversalError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/view/{path:path}")
def view_file(path: str, mp: str = Depends(get_master_password)):
    norm = _validated_path(path)
    cfg = get_storage_config()
    with open_storage(cfg) as st:
        content = st.download_bytes(norm).decode("utf-8", errors="replace")
    return PlainTextResponse(content)


@app.get("/api/verify/{path:path}")
def verify_file(path: str, mp: str = Depends(get_master_password)):
    """Weryfikacja zawartości configu (moduł audit) — zwraca listę uwag
    z poziomami error/warning/info do wyświetlenia w modalu."""
    norm = _validated_path(path)
    cfg = get_storage_config()
    with open_storage(cfg) as st:
        content = st.download_bytes(norm).decode("utf-8", errors="replace")
    findings = run_audit(content)
    return {"file": posixpath.basename(norm),
            "findings": findings,
            "counts": {lvl: sum(1 for f in findings if f["level"] == lvl)
                       for lvl in ("error", "warning", "info")}}


@app.get("/api/download/{path:path}")
def download_file(path: str, mp: str = Depends(get_master_password)):
    norm = _validated_path(path)
    cfg = get_storage_config()
    with open_storage(cfg) as st:
        data = st.download_bytes(norm)
    filename = posixpath.basename(norm)
    return StreamingResponse(
        iter([data]),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.delete("/api/version/{path:path}")
def delete_version(path: str, mp: str = Depends(get_master_password)):
    norm = _validated_path(path)
    cfg = get_storage_config()
    with open_storage(cfg) as st:
        st.delete(norm)
        return {"status": "ok"}


# ======================== DIFF ========================

@app.post("/api/compare")
def compare_versions(
    path_a: str = Form(...),
    path_b: str = Form(...),
    ignore_volatile: bool = Form(True),
    collapse_unchanged: bool = Form(True),
    mp: str = Depends(get_master_password),
):
    norm_a = _validated_path(path_a)
    norm_b = _validated_path(path_b)
    cfg = get_storage_config()
    with open_storage(cfg) as st:
        text_a = st.download_bytes(norm_a).decode("utf-8", errors="replace")
        text_b = st.download_bytes(norm_b).decode("utf-8", errors="replace")

    html, stats = make_diff_html(
        text_a, text_b,
        posixpath.basename(norm_a), posixpath.basename(norm_b),
        collapse_unchanged=collapse_unchanged,
        ignore_volatile=ignore_volatile,
    )
    return {"html": html,
            "stats": {"added": stats.added, "removed": stats.removed,
                      "changed": stats.changed}}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/version")
def version_status():
    """Stan wersji."""
    return VERSION_CHECKER.status()
