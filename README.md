# FortiBackup Web

Self-hostowany, webowy menadżer kopii zapasowych konfiguracji **FortiGate**
Backupy lądują na zdalnym magazynie FTP/SFTP, zaszyfrowana
baza urządzeń jest umiejscowiona lokalnie.

Stack: FastAPI + Jinja2 + vanilla JS (Tailwind), docker-compose.

## Funkcje

- **Dwie metody backupu** per urządzenie:
  - *SSH Push* — aplikacja loguje się na FortiGate'a i wykonuje natywne
    `execute backup config sftp|ftp`,
  - *REST API Pull* — pobranie konfiguracji przez API.
- **Wersjonowanie** — każdy backup to osobny plik `<nazwa>_YYYYmmdd_HHMMSS.conf`;
  podgląd, pobieranie, usuwanie wersji.
- **Porównywanie wersji (diff)** z pominięciem pól zmieniających się co backup FortiOS
  (sekrety `ENC`, klucze prywatne, `conf_file_ver`).
- **Harmonogram automatycznych backupów** co urządzenie (co N godzin /
  codziennie / co tydzień). Z uwagi na to, że serwer nie posiada hasła bazy danych w pamięci,
  konieczne jest zalogowanie się przynajmniej raz po restarcie, żeby uruchomić proces harmonogramu.
- **Foldery urządzeń** — grupowanie po lokalizacjach, przenoszenie między
  folderami.
- **Ping / Traceroute** do urządzenia z poziomu UI.
- **Multi-user**

## Instalacja (docker-compose)

Wymagania: Docker + docker-compose, serwer FTP/SFTP na kopie zapasowe.

```bash
git clone https://github.com/HitarashiMiki/FortiBackupManager.git
cd FortiBackupManager

mkdir -p db

docker compose up -d --build
```

Aplikacja nasłuchuje domyślnie na **http://localhost:8080** 

### Wolumeny

| Host | Kontener | Zawartość |
|---|---|---|
| `./db` | `/DB` | zaszyfrowana baza urządzeń (`devices.db`) |
| `fortibackup-data` | `/root/.fortibackup-web` | ustawienia połączenia z magazynem, secret sesji |


### Pierwsza konfiguracja

1. Wejdź na `http://localhost:8080` → nastąpi automatyczne przekierowanie na **/setup**.
2. Podaj dane serwera FTP/SFTP (host, port, użytkownik, hasło,
   katalog bazowy). Użytkownik na serwerze FTP/SFTP musi mieć
   uprawnienia do zapisu plików.
3. Przejdź do logowania i podaj **hasło główne** — przy pierwszym logowaniu
   tworzy ono nową, zaszyfrowaną bazę urządzeń. To hasło szyfruje wszystkie
   dane dostępowe do FortiGate'ów: nie da się go odzyskać ani zresetować.
4. Dodaj urządzenia i (opcjonalnie) włącz im harmonogram.

### Aktualizacja

```bash
git pull
docker compose up -d --build
```

Baza urządzeń posiada wbudowaną kontrolę wersji - nie można jej
otworzyć przez starszą wersję aplikacji.

## Setup without docker(not supported for bugfixing)

```bash
pip install -r requirements.txt
# baza urządzeń trafia domyślnie do /DB — poza kontenerem wskaż inny katalog:
export FORTIBACKUP_DB_DIR=./db     # Windows (PowerShell): $env:FORTIBACKUP_DB_DIR=".\db"
uvicorn app.main:app --reload
```

Ping/traceroute w UI wymagają obecności `ping` i `traceroute`/`tracert`
w systemie.

## Uwagi bezpieczeństwa

- Hasło główne nigdy nie jest zapisywane na dysku ani w plikach cookie.
- Przy użyciu reverse proxy z TLS (np. Caddy) ustaw `https_only=True`
  w `app/main.py`.
