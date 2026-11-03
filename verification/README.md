# Verification runs

This directory contains read-only verification records for P-ASM.

Each run is written to `verification/runs/<UTC timestamp>/` and includes:

- `verification_report.md`: short human-readable record;
- `verification_report.json`: tool availability, API configuration presence,
  hashes of the existing input files, local inventory counts, and command results.

The verification runner never overwrites files in `scans/` or `normalizers/`.
It does not perform active HTTP probing, exploitation, port scanning, or any
non-passive action.
