"""Pattern + checksum detectors. No models, no network, no I/O."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Iterator

from .checksums import gstin_check_char, verhoeff_ok


class Kind(str, Enum):
    AADHAAR = "aadhaar"
    PAN = "pan"
    GSTIN = "gstin"
    IFSC = "ifsc"
    UPI = "upi"


class Certainty(str, Enum):
    CHECKSUM = "checksum"      # passed a published check digit
    STRUCTURAL = "structural"  # format holds up, but no checksum exists
    WEAK = "weak"              # shape only


@dataclass(frozen=True)
class Hit:
    kind: Kind
    certainty: Certainty
    start: int
    end: int
    masked: str
    note: str = ""

    def __str__(self) -> str:
        return f"{self.kind.value}/{self.certainty.value} @{self.start}:{self.end} {self.masked}"


# --- aadhaar ---------------------------------------------------------------

# UIDAI never issues a number starting 0 or 1. Separators are everywhere in
# real data, so allow space and hyphen between the groups of four.
_AADHAAR = re.compile(r"(?<!\d)([2-9]\d{3})[ \-]?(\d{4})[ \-]?(\d{4})(?!\d)")


def aadhaar(text: str) -> Iterator[Hit]:
    for m in _AADHAAR.finditer(text):
        raw = "".join(m.groups())
        if not verhoeff_ok(raw):
            continue
        # The number itself does not leave this function. Ever. Masking is not
        # a nicety here: a discovery tool that logs Aadhaar is the breach.
        yield Hit(Kind.AADHAAR, Certainty.CHECKSUM, m.start(), m.end(),
                  "XXXX XXXX " + raw[-4:], "value withheld")


# --- pan -------------------------------------------------------------------

# 4th char is the holder type. Anything outside this set is not a PAN, and
# that single check kills most of the false positives.
_HOLDER = {
    "P": "individual", "C": "company", "H": "huf", "F": "firm/llp",
    "A": "aop", "T": "trust", "B": "boi", "L": "local authority",
    "G": "government", "J": "artificial juridical person",
    "K": "krish", "E": "llp",
}

_PAN = re.compile(r"(?<![A-Z0-9])[A-Z]{3}([A-Z])[A-Z](\d{4})[A-Z](?![A-Z0-9])")


def pan(text: str) -> Iterator[Hit]:
    for m in _PAN.finditer(text.upper()):
        holder, digits = m.group(1), m.group(2)
        if holder not in _HOLDER:
            continue
        raw = m.group(0)
        # ABCPA1111A and friends. Real PANs rarely look like this.
        weak = len(set(digits)) == 1
        yield Hit(
            Kind.PAN,
            Certainty.WEAK if weak else Certainty.STRUCTURAL,
            m.start(), m.end(),
            raw[:3] + "XXXXX" + raw[-2:],
            "repeated digits" if weak else _HOLDER[holder],
        )


# --- gstin -----------------------------------------------------------------

# 01-38 are the states and UTs, 97 is "other territory", 99 is centre.
_STATES = set(range(1, 39)) | {97, 99}

_GSTIN = re.compile(
    r"(?<![A-Z0-9])(\d{2})[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z](?![A-Z0-9])"
)


def gstin(text: str) -> Iterator[Hit]:
    for m in _GSTIN.finditer(text.upper()):
        raw = m.group(0)
        if int(m.group(1)) not in _STATES:
            continue
        if gstin_check_char(raw[:14]) != raw[14]:
            continue
        # chars 3-12 are a PAN, so a GSTIN hit is also a PAN hit
        yield Hit(Kind.GSTIN, Certainty.CHECKSUM, m.start(), m.end(),
                  raw[:2] + "XXXXXXXXXX" + raw[12:], f"state {m.group(1)}, embeds pan")


# --- ifsc ------------------------------------------------------------------

_IFSC = re.compile(r"(?<![A-Z0-9])([A-Z]{4})0[A-Z0-9]{6}(?![A-Z0-9])")


def ifsc(text: str) -> Iterator[Hit]:
    for m in _IFSC.finditer(text.upper()):
        # branch codes are public, nothing to mask
        yield Hit(Kind.IFSC, Certainty.STRUCTURAL, m.start(), m.end(),
                  m.group(0), f"bank {m.group(1)}")


# --- upi -------------------------------------------------------------------

_VPA = re.compile(r"(?<![\w.])([\w.\-]{3,60})@([a-zA-Z]{2,20})(?![\w.])")

# Without a handle list every email in the estate is a false positive. This
# list goes stale; it is data, not logic, so keep it easy to extend.
HANDLES = {
    # apps and wallets
    "abfspay", "airtel", "apl", "axisb", "axl", "fam", "freecharge", "ibl",
    "ikwik", "jio", "jupiteraxis", "naviaxis", "paytm", "pingpay", "pockets",
    "ptaxis", "pthdfc", "ptsbi", "ptyes", "superyes", "upi", "waaxis",
    "wahdfcbank", "waicici", "wasbi", "yapl", "ybl", "yespay",
    # google pay
    "okaxis", "okhdfcbank", "okicici", "oksbi",
    # banks
    "aubank", "axisbank", "barodampay", "boi", "centralbank", "citi", "cnrb",
    "dbs", "equitas", "fbl", "federal", "hdfcbank", "hsbc", "icici", "idbi",
    "idfcbank", "indianbank", "indus", "kbl", "kmbl", "kotak", "kvb", "mahb",
    "pnb", "rbl", "sbi", "sib", "uco", "unionbank", "yesbank",
}


def upi(text: str) -> Iterator[Hit]:
    for m in _VPA.finditer(text):
        handle = m.group(2).lower()
        if handle not in HANDLES:
            continue
        yield Hit(Kind.UPI, Certainty.STRUCTURAL, m.start(), m.end(),
                  m.group(1)[:2] + "***@" + handle, "known psp handle")


ALL: tuple[Callable[[str], Iterator[Hit]], ...] = (aadhaar, pan, gstin, ifsc, upi)
