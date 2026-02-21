# Precision Benchmarks

This benchmark tracks scan noise against real open-source repositories.

## Why this exists

- False positives are the fastest way to lose trust in a scanner.
- We need a repeatable signal that shows whether rule updates improve or worsen precision.

## Scope

- Target list: `benchmarks/repos.csv`
- Scanner: current `keyburn` code in this repo
- Outputs:
  - `benchmarks/results/latest.json`
  - `benchmarks/results/latest.md`

## Run locally

```bash
python scripts/benchmark_precision.py
```

Run strict mode (fail if a target cannot be cloned/scanned):

```bash
python scripts/benchmark_precision.py --strict
```

## Interpreting results

- `PASS`: findings stayed at or below `expected_max_findings`
- `REVIEW`: findings exceeded threshold and should be triaged
- `ERROR`: target repo could not be cloned or scanned

This is a precision/noise benchmark. It does not claim full recall coverage.
