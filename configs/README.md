# configs/

- `splits.yaml` — train/dev/test dates (shared; change only via docs/DECISIONS.md)
- `<component>/*.yaml` — one file per experiment, e.g. `configs/cwe/deberta_hier.yaml`.
  Pass the path to your training/eval script and record it in the result file (`config` field).
