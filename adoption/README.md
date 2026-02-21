# Adoption Loop

This loop is for running Keyburn against real external repositories and tracking
noise quality over time.

## Targets

Edit `adoption/targets.csv` to add or remove repositories.

## Run

```bash
python scripts/adoption_loop.py
```

Outputs:

- `adoption/results/latest.json`
- `adoption/results/latest.md`

## Metrics captured

- findings by severity
- findings per KLOC
- suppression marker count (`# keyburn:ignore`, `# kb:ignore`, `# noqa: keyburn`)
- top triggered rules
- scan duration

This is an operational adoption metric, not a formal recall benchmark.
