# -*- coding: utf-8 -*-
"""
storage.py — warstwa dostępu do zdalnego magazynu kopii zapasowych.

Obsługiwane protokoły: SFTP (paramiko) oraz FTP / FTPS (ftplib).
Wszystkie dane programu (backupy + zaszyfrowana baza urządzeń) żyją
wyłącznie na tym zdalnym zasobie — nic nie jest trzymane lokalnie.
"""

from __future__ import annotations

import ftplib
import io
import posixpath
import socket
import stat
import time
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

CONNECT_TIMEOUT = 15  # sekundy (TCP + banner)
AUTH_TIMEOUT = 30     # sekundy (uwierzytelnianie bywa wolniejsze)


class StorageError(Exception):
    """Błąd komunikacji ze zdalnym magazynem."""


@dataclass
class RemoteFile:
    name: str
    path: str
    size: int = 0
    mtime: Optional[datetime] = None


@dataclass
class StorageConfig:
    protocol: str = "sftp"          # "sftp" | "ftp" | "ftps"
    host: str = ""
    port: int = 22
    username: str = ""
    password: str = ""
    base_path: str = "/fortibackup"  # katalog bazowy na serwerze

    def summary(self) -> str:
        return f"{self.protocol}://{self.username}@{self.host}:{self.port}{self.base_path}"


# --------------------------------------------------------------------------- #
#  Interfejs
# --------------------------------------------------------------------------- #

class RemoteStorage:
    """Wspólny interfejs dla backendów magazynu."""

    def __init__(self, cfg: StorageConfig):
        self.cfg = cfg

    def connect(self) -> None: ...
    def close(self) -> None: ...
    def ensure_dir(self, path: str) -> None: ...
    def list_files(self, path: str) -> List[RemoteFile]: ...
    def upload_bytes(self, data: bytes, path: str) -> None: ...
    def download_bytes(self, path: str) -> bytes: ...
    def delete(self, path: str) -> None: ...
    def exists(self, path: str) -> bool: ...

    def join(self, *parts: str) -> str:
        return posixpath.join(self.cfg.base_path, *parts)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()


# --------------------------------------------------------------------------- #
#  SFTP (paramiko)
# --------------------------------------------------------------------------- #

class SFTPStorage(RemoteStorage):
    def __init__(self, cfg: StorageConfig):
        super().__init__(cfg)
        self._transport = None
        self._sftp = None

    def connect(self) -> None:
        import paramiko
        last_err = None
        for attempt in (1, 2):
            try:
                # Własny socket z timeoutem — bez tego nieodpowiadający serwer
                # potrafi zawiesić połączenie na bardzo długo.
                sock = socket.create_connection(
                    (self.cfg.host, self.cfg.port), timeout=CONNECT_TIMEOUT)
                self._transport = paramiko.Transport(sock)
                self._transport.banner_timeout = CONNECT_TIMEOUT
                # auth bywa wolniejszy niż handshake (obciążony serwer,
                # limity sshd) — dajemy mu więcej czasu
                self._transport.auth_timeout = AUTH_TIMEOUT
                self._transport.connect(username=self.cfg.username,
                                        password=self.cfg.password)
                self._transport.set_keepalive(15)
                self._sftp = paramiko.SFTPClient.from_transport(self._transport)
                self._sftp.get_channel().settimeout(60)
                return
            except paramiko.AuthenticationException as e:
                self.close()
                # "Authentication timeout" = serwer nie zdążył odpowiedzieć —
                # warto ponowić; błędne hasło ponawiamy też raz (nieszkodliwe)
                last_err = StorageError(
                    f"SFTP {self.cfg.host}:{self.cfg.port} — uwierzytelnianie: {e}")
            except (paramiko.SSHException, socket.error, OSError) as e:
                self.close()
                last_err = StorageError(
                    f"Nie można połączyć się z SFTP {self.cfg.host}:{self.cfg.port}: {e}")
            if attempt == 1:
                time.sleep(2)
        raise last_err

    def close(self) -> None:
        try:
            if self._sftp:
                self._sftp.close()
            if self._transport:
                self._transport.close()
        except Exception:
            pass
        finally:
            self._sftp = None
            self._transport = None

    def ensure_dir(self, path: str) -> None:
        parts = [p for p in path.split("/") if p]
        cur = "/"
        for p in parts:
            cur = posixpath.join(cur, p)
            try:
                self._sftp.stat(cur)
            except FileNotFoundError:
                try:
                    self._sftp.mkdir(cur)
                except OSError as e:
                    raise StorageError(
                        f"Nie można utworzyć katalogu {cur}: {e}\n"
                        "(przy chroot-owanym SFTP korzeń bywa tylko do odczytu — "
                        "ustaw katalog bazowy wewnątrz zapisywalnego podkatalogu)"
                    ) from e

    def list_files(self, path: str) -> List[RemoteFile]:
        try:
            entries = self._sftp.listdir_attr(path)
        except FileNotFoundError:
            return []
        out: List[RemoteFile] = []
        for a in entries:
            if stat.S_ISDIR(a.st_mode or 0):
                continue
            out.append(RemoteFile(
                name=a.filename,
                path=posixpath.join(path, a.filename),
                size=a.st_size or 0,
                mtime=datetime.fromtimestamp(a.st_mtime) if a.st_mtime else None,
            ))
        return out

    def upload_bytes(self, data: bytes, path: str) -> None:
        self.ensure_dir(posixpath.dirname(path))
        try:
            with self._sftp.open(path, "wb") as f:
                f.write(data)
        except OSError as e:
            raise StorageError(f"Błąd zapisu {path}: {e}") from e

    def download_bytes(self, path: str) -> bytes:
        try:
            with self._sftp.open(path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            raise StorageError(f"Plik nie istnieje: {path}")
        except OSError as e:
            raise StorageError(f"Błąd odczytu {path}: {e}") from e

    def delete(self, path: str) -> None:
        try:
            self._sftp.remove(path)
        except OSError as e:
            raise StorageError(f"Nie można usunąć {path}: {e}") from e

    def exists(self, path: str) -> bool:
        try:
            self._sftp.stat(path)
            return True
        except FileNotFoundError:
            return False


# --------------------------------------------------------------------------- #
#  FTP / FTPS (ftplib)
# --------------------------------------------------------------------------- #

class FTPStorage(RemoteStorage):
    def __init__(self, cfg: StorageConfig):
        super().__init__(cfg)
        self._ftp: Optional[ftplib.FTP] = None

    def connect(self) -> None:
        try:
            if self.cfg.protocol == "ftps":
                ftp = ftplib.FTP_TLS()
            else:
                ftp = ftplib.FTP()
            ftp.connect(self.cfg.host, self.cfg.port, timeout=CONNECT_TIMEOUT)
            ftp.login(self.cfg.username, self.cfg.password)
            if isinstance(ftp, ftplib.FTP_TLS):
                ftp.prot_p()
            self._ftp = ftp
        except ftplib.all_errors as e:  # type: ignore[misc]
            raise StorageError(
                f"Nie można połączyć się z FTP {self.cfg.host}:{self.cfg.port}: {e}") from e

    def close(self) -> None:
        if self._ftp:
            try:
                self._ftp.quit()
            except Exception:
                try:
                    self._ftp.close()
                except Exception:
                    pass
        self._ftp = None

    def ensure_dir(self, path: str) -> None:
        parts = [p for p in path.split("/") if p]
        cur = ""
        for p in parts:
            cur = cur + "/" + p
            try:
                self._ftp.mkd(cur)
            except ftplib.error_perm as e:
                # 550 = już istnieje / brak uprawnień — "istnieje" ignorujemy
                if not str(e).startswith("550"):
                    raise StorageError(f"Błąd tworzenia katalogu {cur}: {e}") from e

    def list_files(self, path: str) -> List[RemoteFile]:
        out: List[RemoteFile] = []
        try:
            for name, facts in self._ftp.mlsd(path):
                if facts.get("type") != "file":
                    continue
                mtime = None
                if "modify" in facts:
                    try:
                        mtime = datetime.strptime(facts["modify"][:14], "%Y%m%d%H%M%S")
                    except ValueError:
                        pass
                out.append(RemoteFile(
                    name=name,
                    path=posixpath.join(path, name),
                    size=int(facts.get("size", 0) or 0),
                    mtime=mtime,
                ))
            return out
        except ftplib.error_perm as e:
            if str(e).startswith("550"):
                return []
        except ftplib.all_errors:
            pass
        # Fallback: NLST (bez metadanych)
        try:
            for name in self._ftp.nlst(path):
                base = posixpath.basename(name)
                full = posixpath.join(path, base)
                try:
                    size = self._ftp.size(full) or 0
                except ftplib.all_errors:
                    continue  # prawdopodobnie katalog
                out.append(RemoteFile(name=base, path=full, size=size))
        except ftplib.error_perm as e:
            if str(e).startswith("550"):
                return []
            raise StorageError(f"Błąd listowania {path}: {e}") from e
        return out

    def upload_bytes(self, data: bytes, path: str) -> None:
        self.ensure_dir(posixpath.dirname(path))
        try:
            self._ftp.storbinary(f"STOR {path}", io.BytesIO(data))
        except ftplib.all_errors as e:
            raise StorageError(f"Błąd zapisu {path}: {e}") from e

    def download_bytes(self, path: str) -> bytes:
        buf = io.BytesIO()
        try:
            self._ftp.retrbinary(f"RETR {path}", buf.write)
        except ftplib.error_perm as e:
            if str(e).startswith("550"):
                raise StorageError(f"Plik nie istnieje: {path}") from e
            raise StorageError(f"Błąd odczytu {path}: {e}") from e
        return buf.getvalue()

    def delete(self, path: str) -> None:
        try:
            self._ftp.delete(path)
        except ftplib.all_errors as e:
            raise StorageError(f"Nie można usunąć {path}: {e}") from e

    def exists(self, path: str) -> bool:
        try:
            self._ftp.size(path)
            return True
        except ftplib.all_errors:
            return False


# --------------------------------------------------------------------------- #
#  Lokalny dysk (używany opcjonalnie dla bazy urządzeń)
# --------------------------------------------------------------------------- #

class LocalStorage(RemoteStorage):
    """Magazyn na lokalnym dysku. Backupy ZAWSZE lądują na zdalnym FTP/SFTP —
    ten backend służy wyłącznie do opcjonalnego trzymania bazy urządzeń
    lokalnie (baza pozostaje zaszyfrowana hasłem głównym)."""

    def connect(self) -> None:
        from pathlib import Path
        Path(self.cfg.base_path).mkdir(parents=True, exist_ok=True)

    def close(self) -> None:
        pass

    def ensure_dir(self, path: str) -> None:
        from pathlib import Path
        try:
            Path(path).mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise StorageError(f"Nie można utworzyć katalogu {path}: {e}") from e

    def list_files(self, path: str) -> List[RemoteFile]:
        from pathlib import Path
        p = Path(path)
        if not p.is_dir():
            return []
        out: List[RemoteFile] = []
        for f in p.iterdir():
            if f.is_file():
                st = f.stat()
                out.append(RemoteFile(
                    name=f.name, path=str(f), size=st.st_size,
                    mtime=datetime.fromtimestamp(st.st_mtime)))
        return out

    def upload_bytes(self, data: bytes, path: str) -> None:
        from pathlib import Path
        p = Path(path)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        except OSError as e:
            raise StorageError(f"Błąd zapisu {path}: {e}") from e

    def download_bytes(self, path: str) -> bytes:
        from pathlib import Path
        p = Path(path)
        if not p.is_file():
            raise StorageError(f"Plik nie istnieje: {path}")
        try:
            return p.read_bytes()
        except OSError as e:
            raise StorageError(f"Błąd odczytu {path}: {e}") from e

    def delete(self, path: str) -> None:
        from pathlib import Path
        try:
            Path(path).unlink()
        except OSError as e:
            raise StorageError(f"Nie można usunąć {path}: {e}") from e

    def exists(self, path: str) -> bool:
        from pathlib import Path
        return Path(path).is_file()


def open_local_db_storage() -> "LocalStorage":
    """Lokalny magazyn na bazę urządzeń: ~/.fortibackup/"""
    from pathlib import Path
    cfg = StorageConfig(protocol="local",
                        base_path=str(Path.home() / ".fortibackup"))
    return LocalStorage(cfg)


# --------------------------------------------------------------------------- #

def open_storage(cfg: StorageConfig) -> RemoteStorage:
    """Fabryka: zwraca odpowiedni backend wg konfiguracji."""
    if cfg.protocol == "sftp":
        return SFTPStorage(cfg)
    if cfg.protocol in ("ftp", "ftps"):
        return FTPStorage(cfg)
    if cfg.protocol == "local":
        return LocalStorage(cfg)
    raise StorageError(f"Nieznany protokół: {cfg.protocol}")
