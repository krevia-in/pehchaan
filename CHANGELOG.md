# Changelog

## 0.1.2

- README rewritten; corrected example scores
- Contact address is now admin@krevia.in

## 0.1.1

First release on PyPI. Same code as 0.1.0; the 0.1.0 filename was
unavailable on PyPI.

## 0.1.0

First release.

- Aadhaar with Verhoeff validation, value masked at source
- PAN with holder type validation
- GSTIN with base 36 checksum and state code validation
- IFSC and UPI VPA against a known PSP handle list
- Context scoring by column name, record contents and environment
- `pehchaan` CLI for files and CSVs

Scoring context is bounded to one record. The first working version scored
against a sliding byte window, which let a fixture comment in one part of a
file suppress live data in another. Fixed before release.
