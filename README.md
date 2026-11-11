# pehchaan

[![PyPI](https://img.shields.io/pypi/v/pehchaan)](https://pypi.org/project/pehchaan/)
[![Python](https://img.shields.io/pypi/pyversions/pehchaan)](https://pypi.org/project/pehchaan/)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)

**Find Aadhaar, PAN, GSTIN and UPI IDs sitting in your data, rank how exposed
each one is, and hide them.**

*pehchaan* (पहचान) means "identity", and also "recognition".

```
pip install pehchaan
```

Zero dependencies. No network calls. No ML model. Pure Python, 3.10+.

---

## Why this exists

Aadhaar and PAN numbers end up in places nobody planned for: CSV exports
emailed around, log files, support tickets, test databases copied from
production, spreadsheets on shared drives. Each copy is one more place an
attacker can find them, and one more place a company doesn't know it has to
protect.

You can't protect data you don't know you have. Under India's DPDP Act, every
company holding personal data has to know where it lives. The first step is
finding the identifiers, and the next is hiding the ones that don't need to
be there.

The usual tool for this is a regex. A twelve-digit Aadhaar regex matches phone
numbers with a `91` prefix, order IDs and UPI reference numbers. Without digit
boundaries, it also matches inside every millisecond timestamp. A scan returns
forty thousand "Aadhaar numbers", nobody can triage them, and the check gets
switched off.

pehchaan does three things:

1. **It validates check digits where they exist.** Aadhaar carries a Verhoeff
   check digit and GSTIN a base-36 checksum. A random twelve-digit number has
   a one in ten chance of passing Verhoeff, so this alone removes about 90% of
   the noise. On 300,000 synthetic phone numbers, order IDs and UPI reference
   numbers, a plain 12-digit regex flagged all of them; Verhoeff flagged
   28,623.
2. **It scores every hit on where it was found.** A value in a column called
   `CUST_PAN_NO`, next to a name and a date of birth, in production, is
   almost certainly real. The same characters in `EXT_REF_03` on a UAT box,
   next to the word "sample", almost certainly aren't. You get a ranked list
   you can work through from the top, not a pile of matches.
3. **It hides what it finds.** One command writes a copy of a file with every
   Aadhaar, PAN, GSTIN and UPI ID masked, and everything else untouched.

## Hide identifiers

```python
from pehchaan import redact

redact("Aadhaar 3642 0577 2018, PAN ABCPN1234F, pay priya.n@okhdfcbank")
# 'Aadhaar XXXX XXXX 2018, PAN ABCXXXXX4F, pay pr***@okhdfcbank'

redact("PAN ABCPN1234F", style="label")    # 'PAN [PAN]'
redact("3642-0577-2018", style="full")     # 'XXXX-XXXX-XXXX'
```

From the shell, this writes `customers.redacted.csv` next to the original and
never changes the original:

```
pehchaan --redact customers.csv
pehchaan --redact --style label support-tickets.txt
```

```
name,aadhaar,pan_no,upi,notes
Priya Nair,XXXX XXXX 2018,ABCXXXXX4F,pr***@okhdfcbank,kyc done
```

| Style | Aadhaar | PAN |
| --- | --- | --- |
| `mask` (default) | `XXXX XXXX 2018` | `ABCXXXXX4F` |
| `label` | `[AADHAAR]` | `[PAN]` |
| `full` | `XXXX XXXX XXXX` | `XXXXXXXXXX` |

Redaction hides everything that is detected, whatever its score. When you
are hiding data, missing one is the failure that matters. IFSC codes are
public bank branch codes, so they are left alone unless you pass
`kinds=[Kind.IFSC]`.

## Quick start

```python
from pehchaan import scan, Scope

row = "name Priya Nair dob 1990-04-12 mobile 9876543210 pan_no ABCPN1234F"

for f in scan("ABCPN1234F",
              Scope(container="CUSTOMERS", field="CUST_PAN_NO", environment="prod"),
              context=row):
    print(f.score, f.hit.kind.value, f.hit.masked)
    print(f.why)
```

```
90 pan ABCXXXXX4F
('base 40 (structural)', '+30 column CUST_PAN_NO names it', '+20 3 identity term(s) in record')
```

Every finding carries `why`, so a reviewer can see how the score was reached
instead of having to trust a number.

### Scanning database rows

```python
from pehchaan import scan_rows, Scope

rows = [
    (value, Scope(source="oracle://PRD/CRM", container=table,
                  field=column, environment="prod"))
    for table, column, value in cursor
]

for f in scan_rows(rows):          # sorted, highest score first
    if f.score >= 70:
        print(f)
```

### Free text and files

```python
from pehchaan import scan_text

for f in scan_text(open("export.txt").read()):
    print(f)
```

`scan_text` splits on blank lines, so each paragraph or block is scored on its
own.

### Command line

```
pehchaan --env prod customers.csv
pehchaan --env uat --min 60 --json dump.csv > findings.json
pehchaan --redact customers.csv
```

For CSVs, each cell is scanned and scored against its whole row, so the
column name and the neighbouring values both count.

The CLI exits with **2** if anything scores 70 or higher, so you can block a
CI pipeline or a data export on it.

## What it detects

| Identifier | How it is validated | Certainty | Masked as |
| --- | --- | --- | --- |
| Aadhaar | 12 digits, first digit 2–9, Verhoeff check digit | checksum | `XXXX XXXX 2018` |
| GSTIN | State code (01–38, 97, 99), structure, base-36 check character | checksum | `29XXXXXXXXXX1ZY` |
| PAN | Structure, and the 4th character must be a valid holder type | structural | `ABCXXXXX4F` |
| IFSC | 4 letters, a literal `0`, 6 alphanumerics | structural | not masked (branch codes are public) |
| UPI ID | `name@handle`, where the handle is a known PSP | structural | `ra***@okhdfcbank` |

A PAN with all four digits the same (`AAAPA1111A`) is reported as **weak**.
Real PANs rarely look like that, but test fixtures often do.

## How scoring works

The match itself is the weakest signal. Context matters more.

| Signal | Effect |
| --- | --- |
| Base: checksum / structural / weak | 70 / 40 / 15 |
| Column name names the identifier (`PAN_NO`, `aadhaar_num`, `gstin`, `vpa`) | +30 |
| Otherwise, an inline label just before the value (`PAN: ...`) | +20 |
| Name, DOB, address, mobile, email, etc. in the same record | +7 each, up to +20 |
| Synthetic-data wording in the record (`sample`, `dummy`, `fixture`, `test`) | −30 |
| Environment or source path is non-prod (`uat`, `dev`, `staging`, `qa`, ...) | −40 |
| Aadhaar (statutory handling requirements) | +10 |

Scores are clamped to 0–100. The same ten characters, `ABCPN1234F`, in four
places:

| Where | Score |
| --- | --- |
| `CUSTOMERS.CUST_PAN_NO`, prod, row has name, DOB and mobile | **90** |
| `CUSTOMERS.CUST_PAN_NO`, UAT, same row | 50 |
| `ORDERS.EXT_REF_03`, prod, nothing else in the row | 40 |
| A `NOTES` field that says "sample row" | 10 |

### Context never crosses a record

An early version scored each hit against a sliding 160-byte window of
surrounding text. In testing, a single `-- test data` comment in a schema dump
lowered the score of every live record within 160 bytes of it.

In a discovery tool, a false negative is much worse than a false positive: a
missed identifier is data nobody knows about. So context is now limited to
one record (a row, a cell's row, or a text block). A fixture in one record
can't hide real data in another. There is a regression test for this.

## Aadhaar is never returned in full

The full Aadhaar number never leaves the detector. You get the match, its
position and the last four digits, the same form as a masked Aadhaar. It is
never in the result object, the `str()` output, the JSON output or the
`why` trail, and a test checks every field.

A discovery tool that logs the Aadhaar numbers it finds is itself a data
leak. If you need the full value, read it from your own source using the
position pehchaan gives you.

## Checksums

```python
from pehchaan import verhoeff_ok, gstin_ok, verhoeff_digit, gstin_check_char

verhoeff_ok("364205772018")       # True
gstin_ok("29ABCPN1234F1ZY")       # True
gstin_check_char("29ABCPN1234F1Z")  # 'Y'
```

**Verhoeff** (Aadhaar) works over the dihedral group D5. It catches every
single-digit error and every swap of two adjacent digits, which are the two
most common data-entry mistakes.

**GSTIN** uses alternating weights of 1 and 2 over base 36, with the carry
folded back in.

**PAN** has no public check digit. Checking the holder-type character
(P = individual, C = company, H = HUF, F = firm and so on) removes most false
positives, but a PAN match can only ever be *structural*, never *checksum*.
The scoring reflects that.

## Known limitations

- **No OCR.** Scanned KYC packs, PDFs without a text layer and photographed
  forms need text extraction first.
- **No name or address detection.** Doing that well needs a model, and this
  library has no dependencies.
- **Latin script only.** Identifiers written in Devanagari or other Indian
  scripts are not matched.
- **The UPI handle list goes stale.** New PSP handles appear all the time.
  `HANDLES` in `pehchaan.detectors` is a plain set, so you can add to it at
  runtime or send a PR.
- **No passport, voter ID, driving licence or ration card yet.** Formats vary
  by state and year, and the false-positive rate isn't good enough yet.
- **Redaction covers text files only.** Excel, PDF and database tables need to
  be exported to text or CSV first. Names, addresses and phone numbers are
  not hidden.
- **Mobile numbers are not reported** as identifiers. On their own they are
  too common to rank usefully. A `mobile` or `phone` column or label still
  counts as identity context in the record.

## Licence

pehchaan is dual-licensed.

- **AGPL-3.0-only** (this repository). Free for any use, including commercial
  and internal. If you modify it, or offer it as part of a network service,
  your changes must be released under the AGPL too.
- **Commercial licence.** Use pehchaan inside a closed-source product or
  service without the AGPL obligations. It also includes OCR for scanned KYC
  documents, name and address extraction, maintained handle and state tables,
  column-name pattern packs, and support.

See [LICENSING.md](LICENSING.md), or write to **admin@krevia.in**.

## Contributing

The most useful thing you can send is a bug report with a failing case: a
real identifier that wasn't found, or noise that scored too high.

**Never put a real Aadhaar, PAN or GSTIN in an issue.** Generate a valid
fixture instead:

```python
from pehchaan import verhoeff_digit, gstin_check_char

prefix = "36420577201"
print(prefix + str(verhoeff_digit(prefix)))      # valid-checksum Aadhaar

first14 = "29ABCPN1234F1Z"
print(first14 + gstin_check_char(first14))        # valid-checksum GSTIN
```

To work on the code:

```
git clone https://github.com/krevia-in/pehchaan.git
cd pehchaan
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -v
```

---

Built by [Krevia](https://krevia.in).
