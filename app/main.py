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

import platform
import posixpath
import subprocess
import threading
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
                       DBTooNewError, DB_FILENAME)
from .fortigate import run_backup, device_backup_dir
from .diff import make_diff_html
from .changes import changed_flags, detect_and_log
from .audit import run_audit
from .security import (SESSIONS, LOGIN_LIMITER, get_or_create_secret,
                       safe_backup_path, PathTraversalError)
from .jobs import JOBS
from .scheduler import SCHEDULER

app = FastAPI(title="FortiBackup Web", docs_url=None, redoc_url=None)


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
                     "error": "Uzupełnij wymagane pola formularza."},
            status_code=400)
    if path == "/login":
        return templates.TemplateResponse(
            request=request, name="login.html",
            context={"error": "Podaj hasło główne."}, status_code=400)
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


@app.on_event("startup")
def _start_scheduler():
    SCHEDULER.start_once()
app.add_middleware(
    SessionMiddleware,
    secret_key=get_or_create_secret(),
    max_age=8 * 3600,          
    same_site="lax",
    https_only=False,          # ustaw True, gdy stoi za TLS-em (reverse proxy)
)

templates = Jinja2Templates(directory="app/templates")

_DEVICE_PUBLIC_FIELDS = ("name", "host", "port", "username", "method",
                         "api_port", "vdom_enabled", "description", "folder",
                         "sched_enabled", "sched_mode", "sched_every_hours",
                         "sched_time", "sched_weekday")


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
                                      context={"error": None})


@app.post("/login")
def login(request: Request, master_password: str = Form(...)):
    settings = load_settings()
    if not settings.host:
        return RedirectResponse("/setup", status_code=HTTP_302_FOUND)

    client_ip = request.client.host if request.client else "?"
    if not LOGIN_LIMITER.allow(client_ip):
        return templates.TemplateResponse(
            request=request, name="login.html",
            context={"error": "Zbyt dużo prób logowania z tego adresu — odczekaj minutę."})

    try:
        with open_db_storage() as dbst:
            local_path = dbst.join(DB_FILENAME)
            if not dbst.exists(local_path):
                _migrate_db_from_remote(settings, dbst, local_path)
            _load_db(dbst, master_password)
    except WrongPasswordError:
        return templates.TemplateResponse(
            request=request, name="login.html",
            context={"error": "Błędne hasło bazy danych"})
    except DBTooNewError as e:
        # Drugie (obok API/426) miejsce powiadomienia: już przy logowaniu,
        # zanim ktokolwiek zdąży cokolwiek zapisać do bazy.
        return templates.TemplateResponse(
            request=request, name="login.html",
            context={"error": str(e)})
    except DeviceDBError as e:
        return templates.TemplateResponse(
            request=request, name="login.html",
            context={"error": str(e)})
    except Exception as e: 
        return templates.TemplateResponse(
            request=request, name="login.html",
            context={"error": f"Błąd połączenia: {e}"})

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
    if not LOGIN_LIMITER.allow(client_ip):
        return False
    return confirm_password == settings.to_storage_config().password


@app.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request):
    settings = load_settings()
    logged = bool(SESSIONS.get_master_password(request.session.get("token")))
    return templates.TemplateResponse(
        request=request, name="setup.html",
        context={"settings": settings,
                 "configured": bool(settings.host),
                 "logged": logged,
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
                "folders": db.folders}


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
        try:
            db.upsert(device)
            SCHEDULER.refresh()
            return {"status": "ok", "message": f"Dodano urządzenie: {device.name}"}
        except DeviceDBError as e:
            raise HTTPException(status_code=400, detail=str(e))


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
            sched_enabled=sched_enabled, sched_mode=sched_mode,
            sched_every_hours=sched_every_hours, sched_time=sched_time.strip(),
            sched_weekday=sched_weekday,
        )
        try:
            db.upsert(device, old_name=name)
            SCHEDULER.refresh()
            return {"status": "ok", "message": "Urządzenie zaktualizowane"}
        except DeviceDBError as e:
            raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/devices/{name}")
def delete_device(name: str, mp: str = Depends(get_master_password)):
    """Usuwa urządzenie z bazy. Backupy na magazynie zostają nietknięte."""
    with open_db_storage() as st:
        db = _load_db(st, mp)
        db.remove(name)
        SCHEDULER.refresh()
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
        return {"status": "ok", "message": f"Przeniesiono '{name}' → {target}"}


# ======================== FOLDERY ========================

@app.post("/api/folders")
def add_folder(name: str = Form(...), mp: str = Depends(get_master_password)):
    cfg = get_storage_config()
    with open_storage(cfg) as st:
        db = _load_db(st, mp)
        try:
            db.add_folder(name)
        except DeviceDBError as e:
            raise HTTPException(status_code=400, detail=str(e))
        return {"status": "ok", "message": f"Utworzono folder: {name.strip()}"}


@app.delete("/api/folders/{name}")
def delete_folder(name: str, mp: str = Depends(get_master_password)):
    """Usuwa folder; urządzenia z niego zostaną przeniesione poza folder."""
    with open_db_storage() as st:
        db = _load_db(st, mp)
        try:
            moved = db.remove_folder(name)
        except DeviceDBError as e:
            raise HTTPException(status_code=400, detail=str(e))
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
                                   lambda m, n=dev.name: JOBS.log(job, f"[{n}] {m}"))
                    job.ok_count += 1
                except Exception as e:  # noqa: BLE001
                    JOBS.log(job, f"[{dev.name}] BŁĄD: {e}")
                    job.fail_count += 1
                    ok = False
    except Exception as e:  # noqa: BLE001
        JOBS.log(job, f"BŁĄD: {e}")
        ok = False
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


# ======================== VERSIONS ========================

@app.get("/api/versions/{device_name}")
def list_versions(device_name: str, mp: str = Depends(get_master_password)):
    cfg = get_storage_config()
    with open_storage(cfg) as st:
        path = device_backup_dir(st, Device(name=device_name, host=""))
        files = [f for f in st.list_files(path) if not f.name.startswith(".")]
        files.sort(key=lambda f: f.name, reverse=True)
        flags = changed_flags(st, path)
        return {"versions": [
            {"name": f.name, "path": f.path, "size": f.size,
             "mtime": f.mtime.isoformat() if f.mtime else None,
             "changed": flags.get(f.name)}
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
