# -*- coding: utf-8 -*-
"""
diff.py — porównywanie dwóch wersji konfiguracji (silnik z wersji desktop).

Side-by-side jak w GitHubie/Notepad++: numery linii, zielone/czerwone tło,
podświetlenie zmian WEWNĄTRZ zmodyfikowanej linii, zwijanie długich bloków
bez zmian z zachowaniem kontekstu wokół zmian.

Dodatkowo normalize_config() maskuje pola, które FortiOS generuje na nowo
przy każdym eksporcie (sekrety ENC, zaszyfrowane klucze prywatne,
#conf_file_ver) — bez tego diff dwóch identycznych konfiguracji zawsze
pokazuje pozorne zmiany. To samo filtrują Oxidized/RANCID.

Zwraca FRAGMENT HTML (ze scopowanym <style>) do wstrzyknięcia w modal.
"""

from __future__ import annotations

import difflib
import html
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

CONTEXT_LINES = 3   # ile linii kontekstu wokół zmian przy zwijaniu


@dataclass
class DiffStats:
    added: int = 0
    removed: int = 0
    changed: int = 0

    def summary(self) -> str:
        return f"+{self.added}  −{self.removed}  ~{self.changed}"


# --------------------------------------------------------------------------- #
#  Normalizacja ulotnych pól konfiguracji FortiGate
# --------------------------------------------------------------------------- #

_RE_CONF_VER = re.compile(r"^#conf_file_ver=.*$", re.M)
_RE_ENC = re.compile(r"\bENC\s+[A-Za-z0-9+/=]+")
_RE_PEM_KEY = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.S,
)

_MASK_ENC = "ENC <sekret — pominięty w porównaniu>"
_MASK_KEY = "<klucz prywatny — pominięty w porównaniu>"


def _mask_pem(m: "re.Match") -> str:
    # zachowaj liczbę linii, żeby numeracja w diffie się nie rozjeżdżała
    n = len(m.group(0).splitlines())
    return "\n".join([_MASK_KEY] * n)


def normalize_config(text: str) -> str:
    """Maskuje pola zmieniające się przy każdym eksporcie konfiguracji."""
    text = _RE_CONF_VER.sub("#conf_file_ver=<pominięte — zmienia się przy każdym zapisie>", text)
    text = _RE_PEM_KEY.sub(_mask_pem, text)
    text = _RE_ENC.sub(_MASK_ENC, text)
    return text


# --------------------------------------------------------------------------- #
#  Rendering
# --------------------------------------------------------------------------- #

_CSS = """
<style>
  .fbdiff { font-family:'Cascadia Code','Consolas',ui-monospace,monospace;
            font-size:12px; color:#c9d1d9; }
  .fbdiff table { border-collapse:collapse; width:100%; table-layout:fixed; }
  .fbdiff td { vertical-align:top; padding:1px 6px; white-space:pre-wrap;
               word-wrap:break-word; border:0; }
  .fbdiff td.ln { width:44px; color:#6e7681; text-align:right;
                  background:#010409; user-select:none; }
  .fbdiff td.code { width:46%; }
  .fbdiff tr.eq  td.code { background:#0d1117; }
  .fbdiff tr.del td.code.left,  .fbdiff tr.rep td.code.left  { background:#3c1618; }
  .fbdiff tr.ins td.code.right, .fbdiff tr.rep td.code.right { background:#12361f; }
  .fbdiff td.empty { background:#161b22; }
  .fbdiff span.hl-del { background:#8b2e31; border-radius:2px; }
  .fbdiff span.hl-ins { background:#1f6f3d; border-radius:2px; }
  .fbdiff tr.skip td { background:#161b22; color:#8b949e; text-align:center;
                       padding:4px; font-style:italic; }
  .fbdiff .hdr { background:#161b22; color:#e6edf3; font-weight:bold;
                 padding:6px; border-bottom:1px solid #30363d; }
</style>
"""


def _esc(s: str) -> str:
    return html.escape(s, quote=False).replace(" ", "&nbsp;") or "&nbsp;"


def _inline_highlight(a: str, b: str) -> Tuple[str, str]:
    """Podświetlenie zmian wewnątrz zmodyfikowanej linii (jak w Notepad++)."""
    sm = difflib.SequenceMatcher(None, a, b)
    left_parts, right_parts = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        seg_a, seg_b = _esc(a[i1:i2]), _esc(b[j1:j2])
        if tag == "equal":
            left_parts.append(seg_a)
            right_parts.append(seg_b)
        else:
            if seg_a.strip("&nbsp;") or tag in ("delete", "replace"):
                left_parts.append(f'<span class="hl-del">{seg_a}</span>')
            if seg_b.strip("&nbsp;") or tag in ("insert", "replace"):
                right_parts.append(f'<span class="hl-ins">{seg_b}</span>')
    return "".join(left_parts), "".join(right_parts)


def _row(cls: str, ln_l: Optional[int], code_l: Optional[str],
         ln_r: Optional[int], code_r: Optional[str],
         raw: bool = False) -> str:
    cl = code_l if raw and code_l is not None else (_esc(code_l) if code_l is not None else None)
    cr = code_r if raw and code_r is not None else (_esc(code_r) if code_r is not None else None)
    left = (f'<td class="ln">{ln_l or ""}</td>'
            f'<td class="code left{" empty" if cl is None else ""}">{cl or ""}</td>')
    right = (f'<td class="ln">{ln_r or ""}</td>'
             f'<td class="code right{" empty" if cr is None else ""}">{cr or ""}</td>')
    return f'<tr class="{cls}">{left}{right}</tr>'


def make_diff_html(
    text_a: str, text_b: str,
    name_a: str = "Wersja A", name_b: str = "Wersja B",
    collapse_unchanged: bool = True,
    ignore_volatile: bool = True,
) -> Tuple[str, DiffStats]:
    if ignore_volatile:
        text_a = normalize_config(text_a)
        text_b = normalize_config(text_b)

    a = text_a.splitlines()
    b = text_b.splitlines()
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    stats = DiffStats()
    rows: List[str] = []

    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            n = i2 - i1
            if collapse_unchanged and n > CONTEXT_LINES * 2 + 2:
                # kontekst PRZED zwinięciem i PO nim — bez tego zmiany
                # wiszą w próżni i nie wiadomo, w której sekcji configu są
                for k in range(CONTEXT_LINES):
                    rows.append(_row("eq", i1 + k + 1, a[i1 + k], j1 + k + 1, b[j1 + k]))
                hidden = n - CONTEXT_LINES * 2
                rows.append(f'<tr class="skip"><td colspan="4">··· {hidden} linii bez zmian ···</td></tr>')
                for k in range(n - CONTEXT_LINES, n):
                    rows.append(_row("eq", i1 + k + 1, a[i1 + k], j1 + k + 1, b[j1 + k]))
            else:
                for k in range(n):
                    rows.append(_row("eq", i1 + k + 1, a[i1 + k], j1 + k + 1, b[j1 + k]))
        elif tag == "delete":
            for k in range(i2 - i1):
                stats.removed += 1
                rows.append(_row("del", i1 + k + 1, a[i1 + k], None, None))
        elif tag == "insert":
            for k in range(j2 - j1):
                stats.added += 1
                rows.append(_row("ins", None, None, j1 + k + 1, b[j1 + k]))
        elif tag == "replace":
            n = max(i2 - i1, j2 - j1)
            for k in range(n):
                la = a[i1 + k] if i1 + k < i2 else None
                lb = b[j1 + k] if j1 + k < j2 else None
                if la is not None and lb is not None:
                    stats.changed += 1
                    hl, hr = _inline_highlight(la, lb)
                    rows.append(_row("rep", i1 + k + 1, hl, j1 + k + 1, hr, raw=True))
                elif la is not None:
                    stats.removed += 1
                    rows.append(_row("del", i1 + k + 1, la, None, None))
                else:
                    stats.added += 1
                    rows.append(_row("ins", None, None, j1 + k + 1, lb))

    if not (stats.added or stats.removed or stats.changed):
        body = '<div class="hdr">Konfiguracje są identyczne — brak realnych różnic.</div>'
    else:
        header = (f'<table><tr>'
                  f'<td class="hdr" colspan="2">{html.escape(name_a)}</td>'
                  f'<td class="hdr" colspan="2">{html.escape(name_b)}</td></tr>')
        body = header + "".join(rows) + "</table>"

    return f'{_CSS}<div class="fbdiff">{body}</div>', stats
