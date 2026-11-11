"""Turning hits into something an analyst can actually triage.

A raw hit list is useless at scale. Ten thousand findings with no ranking is
the same as zero findings, except you also paid for the scan.

Two things decide the score, and only one of them is in the text:

  1. where the value lives (column name, environment, path)
  2. what sits beside it in the same record

Scope beats text. A ten character string in CUST_PAN_NO is a PAN. The same
string in EXT_REF_03 is probably a reference number someone reused.

Context is bounded to one record. An earlier version of this used a sliding
character window and a single "-- test data" comment in a schema suppressed
every live row within 160 bytes of it. In a security tool a false negative
costs far more than a false positive, so the window is gone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .detectors import ALL, Certainty, Hit, Kind


@dataclass(frozen=True)
class Scope:
    source: str = ""        # oracle://PRD/CRM, /mnt/kyc-archive/2019
    container: str = ""     # table, folder, index
    field: str = ""         # column, json key, form field
    environment: str = ""   # prod, uat, dev; blank if unknown

    def label(self) -> str:
        return ".".join(p for p in (self.container, self.field) if p) \
            or self.source or "(unscoped)"


# Column names carry more signal than any amount of surrounding prose, and
# this is the part a classifier built for US data has no idea about.
FIELD_HINTS: dict[Kind, re.Pattern[str]] = {
    Kind.PAN: re.compile(r"\bpan\b|pan_?(no|num|number|card|id)|income_?tax", re.I),
    Kind.AADHAAR: re.compile(r"aadh?a?ar|\buid\b|uidai|\bekyc\b", re.I),
    Kind.GSTIN: re.compile(r"gst(in)?|tax_?reg", re.I),
    Kind.IFSC: re.compile(r"ifsc|branch_?code|neft|rtgs", re.I),
    Kind.UPI: re.compile(r"\bupi\b|\bvpa\b|payment_?addr", re.I),
}

IDENTITY = re.compile(
    r"\b(name|father|mother|dob|date\s*of\s*birth|address|pin\s*code|pincode"
    r"|mobile|phone|email|customer|applicant|nominee|account|kyc|branch)\b", re.I)

SYNTHETIC = re.compile(
    r"\b(test|dummy|sample|mock|fixture|lorem|example|sandbox|seed|demo"
    r"|placeholder|anonymi[sz]ed|scrubbed|redacted)\b", re.I)

NONPROD = {"uat", "dev", "test", "qa", "staging", "sandbox", "sit", "preprod"}

BASE = {Certainty.CHECKSUM: 70, Certainty.STRUCTURAL: 40, Certainty.WEAK: 15}

# how far back to look for an inline label like "PAN:" or "Aadhaar -"
LABEL_LOOKBACK = 24


@dataclass(frozen=True)
class Finding:
    hit: Hit
    scope: Scope
    score: int
    why: tuple[str, ...]

    def __str__(self) -> str:
        return f"{self.score:3d}  {self.scope.label():<28} {self.hit}"


def rate(hit: Hit, record: str, scope: Scope,
         context: str | None = None) -> Finding:
    """Score one hit against its own record. `record` is one row or chunk."""
    context = record if context is None else context
    n = BASE[hit.certainty]
    why = [f"base {n} ({hit.certainty.value})"]

    hint = FIELD_HINTS.get(hit.kind)
    if hint and scope.field and hint.search(scope.field):
        n += 30
        why.append(f"+30 column {scope.field} names it")
    elif hint and hint.search(record[max(0, hit.start - LABEL_LOOKBACK):hit.start]):
        n += 20
        why.append("+20 inline label names it")

    near = len({m.group(0).lower() for m in IDENTITY.finditer(context)})
    if near:
        bump = min(20, near * 7)
        n += bump
        why.append(f"+{bump} {near} identity term(s) in record")

    if SYNTHETIC.search(context):
        n -= 30
        why.append("-30 synthetic-data wording in record")

    env = scope.environment.lower()
    if env in NONPROD and env:
        n -= 40
        why.append(f"-40 {scope.environment}")
    elif NONPROD & set(re.split(r"[/\\.:]", scope.source.lower())):
        n -= 40
        why.append("-40 non-prod path")

    if hit.kind is Kind.AADHAAR:
        n += 10
        why.append("+10 aadhaar, statutory handling")

    return Finding(hit, scope, max(0, min(100, n)), tuple(why))


def scan(record: str, scope: Scope | None = None,
         context: str | None = None) -> list[Finding]:
    """Scan a single record: one row, one line, one chunk.

    `context` lets a caller score against more than it scans. A CSV reader
    scans one cell but passes the whole row, so a name two columns over still
    counts and a "sample row" note still discounts.
    """
    scope = scope or Scope()
    ctx = record if context is None else context
    return [rate(h, record, scope, ctx) for d in ALL for h in d(record)]


def scan_rows(rows: Iterable[tuple[str, Scope]]) -> list[Finding]:
    out = [f for text, scope in rows for f in scan(text, scope)]
    return sorted(out, key=lambda f: (-f.score, f.hit.start))


def scan_text(text: str, scope: Scope | None = None) -> list[Finding]:
    """Free text. Split on blank lines so one block cannot poison another."""
    scope = scope or Scope()
    out = []
    for offset, chunk in _blocks(text):
        for f in scan(chunk, scope):
            h = f.hit
            moved = Hit(h.kind, h.certainty, h.start + offset, h.end + offset,
                        h.masked, h.note)
            out.append(Finding(moved, f.scope, f.score, f.why))
    return sorted(out, key=lambda f: (-f.score, f.hit.start))


_BLANK_LINE = re.compile(r"\n\s*\n")


def _blocks(text: str):
    """Yield (offset, block) for each blank-line separated block, with the
    block's true position in `text`, whatever the separator length."""
    start = 0
    for m in _BLANK_LINE.finditer(text):
        yield start, text[start:m.start()]
        start = m.end()
    yield start, text[start:]
