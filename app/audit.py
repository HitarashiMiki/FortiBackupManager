# -*- coding: utf-8 -*-
"""
audit.py — moduł weryfikacji konfiguracji FortiGate.

Nie sprawdzamy poprawności składni (config przyszedł z samego FortiGate'a),
tylko ZAWARTOŚĆ: ustawienia, które warto zmienić, przeoczenia, odstępstwa
od dobrych praktyk. Wynik to lista uwag z poziomami error / warning / info.

=============================================================================
JAK DODAĆ WŁASNĄ REGUŁĘ (bez grzebania w reszcie kodu):

Dopisz słownik do listy RULES poniżej. Pola:

  section  — sekcja configu, np. "system global" (z `config system global`);
             działa też w trybie VDOM (sekcja może siedzieć w `config global`).
  setting  — nazwa ustawienia z linii `set <setting> <wartość>`.
  default  — wartość DOMYŚLNA FortiOS dla tego ustawienia. UWAGA: FortiGate
             nie eksportuje wartości domyślnych, więc BRAK linii `set`
             oznacza wartość domyślną — reguły to uwzględniają.
  when     — kiedy reguła ma się odpalić:
               "default"    -> wartość jest domyślna (albo brak `set`)
               "changed"    -> wartość jest inna niż default
               "equals"     -> wartość == pole "value"
               "not_equals" -> wartość != pole "value" (brak `set` liczy się
                               jako default, jeśli podano)
               "present"    -> linia `set` występuje w configu
               "missing"    -> linii `set` nie ma w configu
  value    — wartość porównywana przy "equals"/"not_equals" (inaczej pomiń).
  level    — "error" | "warning" | "info".
  message  — treść uwagi; {value} zostanie podmienione na aktualną wartość,
             {setting} na nazwę ustawienia.

Przykład — ostrzeż, gdy zdalny log serwer jest wyłączony:
  {"section": "log syslogd setting", "setting": "status", "default": "disable",
   "when": "default", "level": "warning",
   "message": "Wysyłka logów do syslog jest wyłączona."},

Do bardziej złożonych weryfikacji (relacje między sekcjami itp.) dopisz
funkcję do listy CUSTOM_CHECKS na dole pliku — dostaje sparsowany config
i zwraca listę uwag przez finding().
=============================================================================
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

LEVELS = ("error", "warning", "info")

RULES: List[dict] = [
    # --- porty administracyjne (config system global) -----------------------
    {"section": "system global", "setting": "admin-ssh-port", "default": "22",
     "when": "default", "level": "warning",
     "message": "Port SSH administracji jest domyślny (22) — rozważ zmianę na niestandardowy."},
    {"section": "system global", "setting": "admin-ssh-port", "default": "22",
     "when": "changed", "level": "info",
     "message": "Port SSH administracji zmieniony na {value}."},

    {"section": "system global", "setting": "admin-telnet-port", "default": "23",
     "when": "default", "level": "warning",
     "message": "Port Telnet administracji jest domyślny (23) — rozważ zmianę na niestandardowy."},
    {"section": "system global", "setting": "admin-telnet-port", "default": "23",
     "when": "changed", "level": "info",
     "message": "Port Telnet administracji zmieniony na {value}."},
]


def finding(level: str, message: str, line: Optional[int] = None,
            rule_id: str = "") -> dict:
    return {"level": level if level in LEVELS else "info",
            "message": message, "line": line, "rule_id": rule_id}


# --------------------------------------------------------------------------- #
#  Mini-parser configu FortiOS
# --------------------------------------------------------------------------- #

_RE_CONFIG = re.compile(r"^\s*config\s+(.+?)\s*$")
_RE_EDIT = re.compile(r'^\s*edit\s+"?([^"]*)"?\s*$')
_RE_SET = re.compile(r'^\s*set\s+(\S+)\s+(.*?)\s*$')
_RE_END = re.compile(r"^\s*end\s*$")
_RE_NEXT = re.compile(r"^\s*next\s*$")


class ParsedConfig:
    """Ustawienia z configu z zachowaniem sekcji i numerów linii.

    settings: mapa sekcja -> {ustawienie: (wartość, nr_linii)}.
    Kluczem sekcji jest nazwa z `config ...` (bez kontekstu edit) — np.
    w trybie VDOM `config global > config system global` i tak trafia
    pod "system global"."""

    def __init__(self):
        self.settings: Dict[str, Dict[str, Tuple[str, int]]] = {}

    def get(self, section: str, setting: str) -> Optional[Tuple[str, int]]:
        return self.settings.get(section, {}).get(setting)


def parse_config(text: str) -> ParsedConfig:
    parsed = ParsedConfig()
    stack: List[str] = []          
    edit_depth = 0                 
    for line_no, raw in enumerate(text.splitlines(), start=1):
        m = _RE_CONFIG.match(raw)
        if m:
            stack.append(m.group(1).strip().strip('"'))
            continue
        if _RE_EDIT.match(raw):
            edit_depth += 1
            continue
        if _RE_NEXT.match(raw):
            edit_depth = max(0, edit_depth - 1)
            continue
        if _RE_END.match(raw):
            if stack:
                stack.pop()
            continue
        m = _RE_SET.match(raw)
        if m and stack:
            section = stack[-1]
            key, value = m.group(1), m.group(2).strip().strip('"')
            parsed.settings.setdefault(section, {}).setdefault(key, (value, line_no))
    return parsed


# --------------------------------------------------------------------------- #
#  Rules engine
# --------------------------------------------------------------------------- #

def _apply_rule(rule: dict, cfg: ParsedConfig) -> Optional[dict]:
    entry = cfg.get(rule["section"], rule["setting"])
    present = entry is not None
    default = rule.get("default")
    # brak `set` = wartość domyślna FortiOS (o ile regułę o nią pytamy)
    value = entry[0] if present else default
    line = entry[1] if present else None
    when = rule.get("when", "present")

    hit = False
    if when == "default":
        hit = default is not None and value == default
    elif when == "changed":
        hit = present and default is not None and value != default
    elif when == "equals":
        hit = value == rule.get("value")
    elif when == "not_equals":
        hit = value != rule.get("value")
    elif when == "present":
        hit = present
    elif when == "missing":
        hit = not present

    if not hit:
        return None
    message = rule["message"].format(value=value, setting=rule["setting"])
    rule_id = f"{rule['section']}/{rule['setting']}/{when}"
    return finding(rule.get("level", "info"), message, line, rule_id)


def run_audit(text: str) -> List[dict]:
    """Uruchamia wszystkie reguły + custom checks. Zwraca uwagi posortowane
    od najpoważniejszych (error -> warning -> info)."""
    cfg = parse_config(text)
    findings: List[dict] = []
    for rule in RULES:
        f = _apply_rule(rule, cfg)
        if f:
            findings.append(f)
    for check in CUSTOM_CHECKS:
        try:
            findings.extend(check(cfg) or [])
        except Exception as e:  # noqa: BLE001 — zła reguła nie psuje reszty
            findings.append(finding(
                "error", f"Weryfikacja '{getattr(check, '__name__', '?')}' "
                         f"nie powiodła się: {e}"))
    order = {lvl: i for i, lvl in enumerate(LEVELS)}
    findings.sort(key=lambda f: (order.get(f["level"], 99), f["line"] or 0))
    return findings


# --------------------------------------------------------------------------- #
#  Weryfikacje niestandardowe (funkcje) — na przyszłość
# --------------------------------------------------------------------------- #
# Każda funkcja dostaje ParsedConfig i zwraca listę uwag, np.:
#
# def check_cos(cfg: ParsedConfig) -> List[dict]:
#     out = []
#     entry = cfg.get("system dns", "primary")
#     if entry and entry[0] == "8.8.8.8":
#         out.append(finding("info", "DNS ustawiony na Google.", entry[1]))
#     return out

CUSTOM_CHECKS: List = []
