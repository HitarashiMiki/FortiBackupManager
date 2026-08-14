# -*- coding: utf-8 -*-
"""
dbcheck.py — diagnostyka pliku bazy urządzeń (narzędzie awaryjne).

Po co: gdy `devices.db` zniknie, zostanie podmieniony albo odtworzony z kopii,
z poziomu UI widać tylko objaw („brak urządzeń", „błędne hasło"). To narzędzie
mówi wprost, co jest w pliku: czy to w ogóle baza FortiBackup, jaki ma schemat,
czy podane hasło ją otwiera i ile urządzeń w niej siedzi.

Uruchomienie w kontenerze:

    docker compose exec -it fortibackup-web python -m app.dbcheck
    docker compose exec -it fortibackup-web python -m app.dbcheck /DB/devices.db /DB/devices.db.backup

Hasło pobierane jest z ukrytego promptu — NIE podawaj go w linii poleceń
(trafiłoby do historii shella). Narzędzie niczego nie zapisuje i nie modyfikuje.
"""

from __future__ import annotations

import getpass
import hashlib
import os
import sys
from typing import List

from .devicedb import (MAGIC, MAGIC_V1, MAGIC_PREFIX, SALT_LEN, DB_FILENAME,
                       decrypt_payload, WrongPasswordError, DBTooNewError,
                       DeviceDBError)

DEFAULT_PATH = os.path.join(os.environ.get("FORTIBACKUP_DB_DIR", "/DB"), DB_FILENAME)


def _describe_header(blob: bytes) -> List[str]:
    """Co da się powiedzieć o pliku BEZ hasła."""
    out = []
    if len(blob) < len(MAGIC) + SALT_LEN:
        out.append("  ! plik za krótki, żeby być bazą urządzeń")
        return out
    magic = blob[:len(MAGIC)]
    if not blob.startswith(MAGIC_PREFIX):
        out.append("  ! to NIE jest baza FortiBackup (brak nagłówka FBK)")
        return out
    name = magic.decode("ascii", errors="replace")
    if magic == MAGIC_V1:
        out.append(f"  nagłówek: {name} (stary schemat, zostanie zmigrowany do FBK2)")
    elif magic == MAGIC:
        out.append(f"  nagłówek: {name}")
    else:
        out.append(f"  nagłówek: {name} — NOWSZY niż ta wersja programu")
    salt = blob[len(MAGIC):len(MAGIC) + SALT_LEN]
    # sól nie jest sekretem (leży jawnie w pliku), a pozwala odróżnić pliki:
    # ta sama sól = ten sam „rodowód" bazy, inna = baza założona od nowa
    out.append(f"  sól: {salt.hex()[:16]}…")
    return out


def inspect(path: str, password: str) -> bool:
    """Wypisuje, co wiadomo o pliku. Zwraca True, gdy hasło go otwiera."""
    print(f"\n{path}")
    if not os.path.isfile(path):
        if os.path.isdir(path):
            print("  ! to KATALOG, nie plik — typowy skutek złego montowania")
        else:
            print("  ! nie istnieje")
        return False

    blob = open(path, "rb").read()
    print(f"  rozmiar: {len(blob)} B")
    print(f"  sha256: {hashlib.sha256(blob).hexdigest()[:16]}…")
    for line in _describe_header(blob):
        print(line)

    try:
        data = decrypt_payload(blob, password)
    except WrongPasswordError:
        print("  → HASŁO NIE PASUJE do tego pliku (albo plik jest uszkodzony)")
        return False
    except DBTooNewError as e:
        print(f"  → {e}")
        return False
    except DeviceDBError as e:
        print(f"  → {e}")
        return False

    devices = data.get("devices", [])
    folders = data.get("folders", [])
    print(f"  → HASŁO PASUJE — schemat {data.get('version', '?')}, "
          f"urządzeń: {len(devices)}, folderów: {len(folders)}")
    if devices:
        names = [d.get("name", "?") for d in devices]
        head = ", ".join(names[:8])
        print(f"  urządzenia: {head}{' …' if len(names) > 8 else ''}")
    else:
        print("  UWAGA: baza otwiera się, ale jest PUSTA "
              "(tak wygląda świeżo założona przez ekran logowania)")
    return True


def main(argv: List[str]) -> int:
    paths = argv[1:] or [DEFAULT_PATH]
    print("dbcheck — diagnostyka bazy urządzeń (tylko odczyt, nic nie zapisuje)")
    password = getpass.getpass("Hasło główne (nie będzie widoczne): ")
    ok = [inspect(p, password) for p in paths]

    print()
    if not any(ok):
        print("Żaden ze sprawdzonych plików nie otwiera się tym hasłem.")
        print("Jeśli plik ma nagłówek FBK i rozsądny rozmiar, to jest to baza —")
        print("tylko zaszyfrowana INNYM hasłem. Hasła nie da się odzyskać.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
