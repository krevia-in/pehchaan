# pehchaan

Finds Indian identifiers in text and tells you how likely each one is to be real.

Most code that does this is a regex somebody pasted from Stack Overflow. Those
regexes fire on phone numbers, order IDs and epoch timestamps, and then somebody
turns the whole check off because the output is noise. This library validates
check digits where they exist and scores everything else on where it was found.

Handles Aadhaar, PAN, GSTIN, IFSC and UPI VPAs. No dependencies, no network
calls, no model inference.

## Install

```
pip install pehchaan
```

## Use

```python
from pehchaan import scan, Scope

for f in scan("PAN: ABCPN1234F", Scope(field="CUST_PAN_NO", environment="prod")):
    print(f.score, f.hit.kind.value, f.hit.masked)
```

```
100 pan ABCXXXXX4F
```

Scanning a lot of rows out of a database:

```python
from pehchaan import scan_rows, Scope

rows = [
    (value, Scope(source="oracle://PRD/CRM", container=table,
                  field=column, environment="prod"))
    for table, column, value in cursor
]

for f in scan_rows(rows):
    if f.score >= 70:
        print(f)
```

From the shell:

```
pehchaan --env prod customers.csv
pehchaan --env uat --min 60 --json dump.csv > findings.json
```

The CLI exits 2 if anything scores 70 or above, so you can gate a pipeline on it.

## Why the scores move

The identifier itself is the weakest signal. These matter more:

| Signal | Effect |
| --- | --- |
| Column named `PAN_NO`, `aadhaar_num`, `gstin` | +30 |
| Inline label, `PAN: ABCPN1234F` | +20 |
| Name, DOB, address, mobile in the same record | up to +20 |
| Words like `sample`, `fixture`, `dummy` in the record | -30 |
| Environment or path says `uat`, `dev`, `staging` | -40 |

The same ten characters score 100 in `VENDOR.TAX_REG_NO` and 40 in
`ORDERS.EXT_REF_03`. That difference is the entire point of the library.

Context never crosses a record boundary. An early version used a sliding
160 byte window, and one `-- test data` comment in a schema file suppressed
every live row near it. In a discovery tool a false negative is much worse
than a false positive, so the window is gone.

## Aadhaar

The number is never returned, logged or stored. You get the fact of a match,
its position, and the last four digits. That is what UIDAI permits for display.

If you need the full value for your own processing, read it from your own
source. This library will not hand it to you, and that is deliberate.

## Checksums

Aadhaar uses Verhoeff, which catches every single digit error and almost every
transposition. GSTIN uses a base 36 alternating weight sum. Both are
implemented here and both are tested against generated fixtures.

PAN has no public check digit. The fourth character is the holder type, and
validating it against the real set removes most false positives, but a PAN can
only ever be reported as structural, not checksum.

```python
from pehchaan import verhoeff_ok, gstin_ok
verhoeff_ok("364205772018")
gstin_ok("29ABCPN1234F1ZY")
```

## Known limitations

- No OCR. Scanned KYC packs and photographed forms need a text layer first.
- Names and addresses are not detected. They need a model, not a regex, and
  that does not belong in a zero dependency library.
- Vernacular scripts are not handled.
- The UPI handle list goes stale. It is a plain set in `detectors.py`, so
  extend it in your own code or send a PR.
- Driving licence, voter ID and passport are not covered. Formats vary by
  issuing state and the false positive rate is not yet acceptable.

## Licence

AGPL-3.0-only. Use it, read it, fork it, ship it inside your own AGPL work.

If you want to use it in something closed source, there is a commercial
licence. See [LICENSING.md](LICENSING.md).

## Contributing

Bug reports with a failing case are the most useful thing you can send. Please
do not put real identifiers in an issue. Generate a fixture instead:

```python
from pehchaan import verhoeff_digit
prefix = "36420577201"
print(prefix + str(verhoeff_digit(prefix)))
```
