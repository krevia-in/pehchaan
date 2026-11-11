"""Hide identifiers in text and leave everything else exactly as it was.

    >>> from pehchaan import redact
    >>> redact("Aadhaar 3642 0577 2018, PAN ABCPN1234F")
    'Aadhaar XXXX XXXX 2018, PAN ABCXXXXX4F'
    >>> redact("PAN ABCPN1234F", style="label")
    'PAN [PAN]'

Scoring does not apply here. Redaction hides everything that is detected,
because when you are hiding data, a false negative is the failure that
matters.
"""

from __future__ import annotations

from collections.abc import Iterable

from .detectors import ALL, Hit, Kind

# IFSC is a public bank branch code, not personal data, so it is left alone
# unless asked for.
DEFAULT_KINDS: frozenset[Kind] = frozenset(
    {Kind.AADHAAR, Kind.PAN, Kind.GSTIN, Kind.UPI})

STYLES = ("mask", "label", "full")


def find(text: str, kinds: Iterable[Kind] | None = None) -> list[Hit]:
    """Every identifier in `text`, in order, with overlaps removed."""
    wanted = DEFAULT_KINDS if kinds is None else frozenset(kinds)
    hits = sorted((h for d in ALL for h in d(text) if h.kind in wanted),
                  key=lambda h: (h.start, -(h.end - h.start)))
    out: list[Hit] = []
    end = -1
    for h in hits:
        if h.start >= end:
            out.append(h)
            end = h.end
    return out


def _replacement(hit: Hit, original: str, style: str) -> str:
    if style == "label":
        return f"[{hit.kind.value.upper()}]"
    if style == "full":
        return "".join("X" if c.isalnum() else c for c in original)
    return hit.masked


def redact(text: str, kinds: Iterable[Kind] | None = None,
           style: str = "mask") -> str:
    """Return `text` with identifiers hidden.

    style="mask"   keep a few characters for reference: XXXX XXXX 2018, ABCXXXXX4F
    style="label"  replace with the type: [AADHAAR], [PAN]
    style="full"   replace every letter and digit with X, keeping the length
    """
    if style not in STYLES:
        raise ValueError(f"style must be one of {', '.join(STYLES)}")
    parts: list[str] = []
    pos = 0
    for h in find(text, kinds):
        parts.append(text[pos:h.start])
        parts.append(_replacement(h, text[h.start:h.end], style))
        pos = h.end
    parts.append(text[pos:])
    return "".join(parts)
