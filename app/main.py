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

import posixpath
import threading
from typing import Optional

from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import (HTMLResponse, RedirectResponse, StreamingResponse,
                               PlainTextResponse, JSONResponse)
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.status import HTTP_302_FOUND, HTTP_401_UNAUTHORIZED

from .config import load_settings, save_settings, AppSettings, _obf
from .storage import open_storage, StorageConfig, StorageError
from .devicedb import (DeviceDB, Device, WrongPasswordError, DeviceDBError,
                       DBTooNewError)
from .fortigate import run_backup, device_backup_dir
from .diff import make_diff_html
from .security import (SESSIONS, LOGIN_LIMITER, get_or_create_secret,
                       safe_backup_path, PathTraversalError)
from .jobs import JOBS
from .scheduler import SCHEDULER

app = FastAPI(title="FortiBackup Web", docs_url=None, redoc_url=None)


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
    max_age=8 * 3600,          # dzień pracy; TTL po stronie serwera też 8h
    same_site="lax",
    https_only=False,          # ustaw True, gdy stoi za TLS-em (reverse proxy)
)

templates = Jinja2Templates(directory="app/templates")

# Pola urządzenia bezpieczne do wysłania do przeglądarki (BEZ sekretów)
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
        raise HTTPException(status_code=400, detail="Baza danych nie jest skonfigurowana")
    return settings.to_storage_config()


def _load_db(st, mp: str) -> DeviceDB:
    db = DeviceDB(st, mp)
    db.load_or_create()
    return db


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
        cfg = settings.to_storage_config()
        with open_storage(cfg) as st:
            _load_db(st, master_password)
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
    except Exception as e:  # noqa: BLE001
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
    (b) znajomość AKTUALNEGO hasła magazynu — ratunek na scenariusz
        "baza przeniesiona, logowanie niemożliwe, a /setup za sesją".
    """
    if SESSIONS.get_master_password(request.session.get("token")):
        return True
    settings = load_settings()
    if not settings.host:
        return True  # świeża instalacja — setup otwarty
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
    password: str = Form(...),
    base_path: str = Form("/fortibackup"),
    confirm_password: str = Form(""),
):
    if not _setup_authorized(request, confirm_password):
        settings = load_settings()
        return templates.TemplateResponse(
            request=request, name="setup.html",
            context={"settings": settings, "configured": True,
                     "logged": False,
                     "error": "Błędne aktualne hasło bazy danych (albo limit prób — odczekaj minutę)."})
    settings = AppSettings(
        protocol=protocol,
        host=host.strip(),
        port=port,
        username=username.strip(),
        password_obf=_obf(password),
        base_path=base_path.strip() or "/fortibackup",
    )
    save_settings(settings)
    SCHEDULER.refresh()
    return RedirectResponse("/login", status_code=HTTP_302_FOUND)


@app.post("/setup/reset")
def reset_setup(request: Request, confirm_password: str = Form("")):
    """Wyczyszczenie konfiguracji magazynu (dane na magazynie zostają
    nietknięte). Autoryzacja jak przy zmianie setupu."""
    if not _setup_authorized(request, confirm_password):
        settings = load_settings()
        return templates.TemplateResponse(
            request=request, name="setup.html",
            context={"settings": settings, "configured": True,
                     "logged": False,
                     "error": "Błędne aktualne hasło bazy danych (albo limit prób — odczekaj minutę)."})
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
    cfg = get_storage_config()
    with open_storage(cfg) as st:
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
    cfg = get_storage_config()
    with open_storage(cfg) as st:
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
    cfg = get_storage_config()
    with open_storage(cfg) as st:
        db = _load_db(st, mp)
        device = db.get(name)
        if not device:
            raise HTTPException(status_code=404, detail="Urządzenie nie istnieje")
        # Sekretów nie wysyłamy do przeglądarki — formularz edycji pokazuje
        # placeholder "pozostaw puste, aby nie zmieniać".
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
    cfg = get_storage_config()
    with open_storage(cfg) as st:
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
            extra=old.extra,   # nieznane pola nowszych wersji — nie wycinaj
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
    """Usuwa urządzenie z bazy. Backupy na magazynie zostają nietknięte —
    świadomie: kopie konfiguracji to ostatnia rzecz, którą chcemy kasować
    kaskadowo."""
    cfg = get_storage_config()
    with open_storage(cfg) as st:
        db = _load_db(st, mp)
        db.remove(name)
        SCHEDULER.refresh()
        return {"status": "ok", "message": f"Usunięto urządzenie: {name}"}


@app.post("/api/devices/{name}/move")
def move_device(name: str, folder: str = Form(""),
                mp: str = Depends(get_master_password)):
    cfg = get_storage_config()
    with open_storage(cfg) as st:
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
    """Usuwa folder; urządzenia z niego lądują poza folderami."""
    cfg = get_storage_config()
    with open_storage(cfg) as st:
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
        with open_storage(cfg) as st:
            db = _load_db(st, mp)
            targets = ([d for d in db.devices if d.name in device_names]
                       if device_names else list(db.devices))
            if not targets:
                JOBS.log(job, "Brak urządzeń do backupu.")
                ok = False
            for dev in targets:
                try:
                    path = run_backup(dev, st, logger=lambda m: JOBS.log(job, m))
                    JOBS.log(job, f"[{dev.name}] OK → {path}")
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
        files = st.list_files(path)
        files.sort(key=lambda f: f.name, reverse=True)
        return {"versions": [
            {"name": f.name, "path": f.path, "size": f.size,
             "mtime": f.mtime.isoformat() if f.mtime else None}
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
    # zwykły tekst — czytelny podgląd po otwarciu w nowej karcie
    return PlainTextResponse(content)


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
