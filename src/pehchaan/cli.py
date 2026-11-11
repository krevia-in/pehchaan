"""pehchaan <path>... - scan files and print ranked findings."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from .scoring import Scope, scan, scan_text


def _csv_rows(path: Path):
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            whole = " ".join(f"{k} {v}" for k, v in row.items() if v)
            for col, val in row.items():
                if val:
                    yield val, Scope(source=str(path), container=path.name,
                                     field=col or ""), whole


def _scan_path(path: Path, env: str):
    if path.suffix.lower() in {".csv", ".tsv"}:
        for text, scope, row in _csv_rows(path):
            yield from scan(text, Scope(scope.source, scope.container,
                                        scope.field, env), context=row)
    else:
        body = path.read_text(encoding="utf-8", errors="replace")
        yield from scan_text(body, Scope(source=str(path), container=path.name,
                                         environment=env))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pehchaan", description=__doc__)
    ap.add_argument("paths", nargs="+", type=Path)
    ap.add_argument("--env", default="", help="prod, uat, dev")
    ap.add_argument("--min", type=int, default=0, help="score floor")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    found = []
    for p in args.paths:
        if not p.exists():
            print(f"pehchaan: {p}: no such file", file=sys.stderr)
            return 1
        found.extend(f for f in _scan_path(p, args.env) if f.score >= args.min)

    found.sort(key=lambda f: -f.score)

    if args.json:
        json.dump([{
            "score": f.score, "kind": f.hit.kind.value,
            "certainty": f.hit.certainty.value, "masked": f.hit.masked,
            "source": f.scope.source, "container": f.scope.container,
            "field": f.scope.field, "why": list(f.why),
        } for f in found], sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        for f in found:
            print(f)
        print(f"\n{len(found)} finding(s)", file=sys.stderr)

    # non-zero when anything scores high, so CI can gate on it
    return 2 if any(f.score >= 70 for f in found) else 0


if __name__ == "__main__":
    raise SystemExit(main())
