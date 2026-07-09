# Zmiany po audycie (2026-07-09)

Struktura i podejście (FastAPI + Jinja2 + vanilla JS) bez zmian.
Wszystkie modyfikacje widoczne przez `git diff`.

## Bezpieczeństwo (krytyczne)

1. **Hasło główne NIE jest już trzymane w cookie.** Starlette
   SessionMiddleware zapisuje sesję w cookie po stronie klienta —
   podpisanym, ale niezaszyfrowanym (base64). Master password był czytelny
   dla każdego, kto zobaczył cookie (przeglądarka, proxy, logi).
   Teraz: cookie zawiera losowy token, hasło żyje wyłącznie w pamięci
   serwera (app/security.py, SessionStore, TTL 8h przesuwane).
   Konsekwencja: restart kontenera wylogowuje wszystkich — celowo.

2. **Secret podpisujący cookie** nie jest już hardcodowany w repo —
   generowany losowo przy pierwszym starcie do
   ~/.fortibackup-web/session_secret (na wolumenie dockera).

3. **Path traversal zablokowany.** /api/view, /api/download i
   DELETE /api/version przyjmowały dowolną ścieżkę — dało się pobrać
   i skasować każdy plik konta magazynu, z devices.db włącznie.
   Teraz ścieżki są normalizowane i muszą leżeć w <base>/backups/.

4. **Sekrety urządzeń nie wychodzą do przeglądarki.** /api/devices
   zwracał hasła SSH i tokeny API plaintextem w JSON-ie. Teraz API zwraca
   tylko pola publiczne + flagi has_password/has_api_token; przy edycji
   puste pole = zachowaj stary sekret.

5. **/setup wymaga zalogowania po pierwszej konfiguracji** — wcześniej
   każdy mógł podmienić serwer magazynu i przekierować backupy do siebie.

6. **Rate limit na /login** (5 prób/min/IP) — ochrona hasła głównego
   przed brute-force.

## Stabilność / poprawność

7. **Endpointy zamienione z `async def` na `def`.** Blokujące
   paramiko/ftplib wewnątrz `async def` zatrzymywało event loop —
   jeden wolny SFTP wieszał aplikację wszystkim użytkownikom.
   Sync def = FastAPI odpala je w threadpoolu.

8. **Backupy jako joby** (app/jobs.py): id, status, log. Frontend
   odpytuje /api/jobs/{id} do faktycznego zakończenia i pokazuje log
   z przebiegu — zamiast print-a do stdout i ogłaszania sukcesu po
   sztywnych 16 sekundach niezależnie od wyniku.

9. **Usunięty htmx** — hx-get na liście urządzeń wstrzykiwał surowy JSON
   do diva (endpoint zwraca JSON, nie HTML); listą i tak zarządzał JS.

10. **Dockerfile bez --reload** (tryb deweloperski w produkcyjnym CMD).

## Diff (podmieniony w całości)

11. Silnik z wersji desktop: side-by-side z numerami linii, podświetlenie
    zmian WEWNĄTRZ zmodyfikowanej linii, zwijanie długich bloków
    z zachowaniem 3 linii kontekstu wokół zmian (poprzednio zwinięte
    bloki znikały bez kontekstu).

12. **Normalizacja pól ulotnych** (checkbox, domyślnie włączona):
    maskowanie sekretów ENC, zaszyfrowanych kluczy prywatnych (PEM)
    i #conf_file_ver — FortiOS generuje je na nowo przy każdym eksporcie,
    więc bez maskowania diff dwóch identycznych konfiguracji zawsze
    pokazywał zmiany. To samo filtrują Oxidized/RANCID.

## Drobne

13. /api/view zwraca text/plain (czytelny podgląd w nowej karcie zamiast
    surowego JSON-a).
14. Wygaśnięta sesja → frontend przekierowuje na /login zamiast sypać
    błędami w konsoli.
15. Cookie: SameSite=lax, max_age 8h. Za reverse proxy z TLS ustawić
    https_only=True w main.py.

## Uwagi wdrożeniowe

- Frontend ciągnie Tailwind/FontAwesome z CDN — kontener bez dostępu do
  internetu wyświetli goły HTML. Do rozważenia vendoring assetów.
- Sesje i joby są w pamięci jednego procesu — uvicorn z 1 workerem
  (domyślnie tak jest). Przy skalowaniu na wielu workerów trzeba
  przenieść SessionStore/JobRegistry np. do Redisa.
