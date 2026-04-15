# pf-signal-forensics

Consumer-side signal lifecycle forensics for the Post Fiat network. Traces each received signal through 6 protocol stages, identifies fate-changing gates, and aggregates failure modes with Wilson confidence intervals and chi-squared independence tests.

Zero external dependencies. Deterministic. Consumer-side only.

## Quick Start

```bash
# trace signals through all 6 protocol stages
python3 trace_signal.py --signals resolved_signals.json --output forensic_report.json

# verify the report (zero-trust, independent recomputation)
python3 verify_forensics.py forensic_report.json

# run tests
python3 -m pytest tests/ -v
```

## What It Does

For each signal, traces through:

1. **Schema validation** — field presence, value ranges, enum compliance
2. **Routing** — 5 sequential gates (regime, duration, confidence, VOI, weak symbol)
3. **Resolution** — direction correctness, karma, Brier score
4. **Aggregation** — reputation-weighted contribution (single-producer pass-through)
5. **Proof inclusion** — rolling window membership, freshness grading
6. **Trust contribution** — accuracy/karma/Brier impact direction

Per signal output includes: stage verdicts, decision rationale, deciding thresholds, and the **fate-changing gate** (the specific protocol check that changed the signal from EMIT to WITHHOLD/INVERT).

Aggregate output includes:
- **Per-gate failure rates** with Wilson 95% CIs
- **Per-symbol gate failure distributions**
- **Failure mode ranking** (most common first)
- **Chi-squared independence test** (are gate failures independent of symbol?)
- **Cramer's V** effect size

## Example Output

From 8,676 real b1e55ed signals (March 19 – April 13 2026), regime gate disabled to reveal secondary gate structure:

```
Signals traced: 8676
Fate changes:   2468 (28.4%)
Pass rate:      71.6%

Per-gate failure rates:
  duration_gate:    400/8676 (4.6%) CI=[4.2%, 5.1%]
  confidence_gate:  28/8676  (0.3%) CI=[0.2%, 0.5%]
  weak_symbol_gate: 2168/8676 (25.0%) CI=[24.1%, 25.9%]

Most impactful gate:  weak_symbol_gate
Most impacted symbol: SOL

Chi-squared: χ²=1855.43, df=6, p=0.0000, V=0.5978 (NOT independent)
```

SOL drives the non-independence: 100% of SOL signals get INVERT action via the weak symbol gate (severity=SEVERE, p=0.0001).

## Files

| File | Description |
|------|-------------|
| `trace_signal.py` | Zero-dep forensics runner (~700 lines) |
| `signal_forensics_schema.json` | JSON Schema draft 2020-12 (20 $defs) |
| `verify_forensics.py` | Zero-trust verifier (958 checks, 17 categories) |
| `tests/test_forensics.py` | 144 tests |
| `examples/forensic_report.json` | Dated report (default policy, all SYSTEMIC) |
| `examples/forensic_report_no_regime_gate.json` | Dated report (regime gate disabled) |

## Verification

```
$ python3 verify_forensics.py examples/forensic_report.json

Signal Forensics Verification — 958 checks
  Total: 958/958 PASS, 0 FAIL — Grade A
```

17 verification categories: structure, version, meta, policy, trace_structure, stage_verdicts, fate_changes, aggregates, gate_rates, wilson_ci, symbol_gates, stage_summary, fate_summary, failure_modes, chi_squared, limitations, content_hash.

## Schema

JSON Schema draft 2020-12 with 20 `$defs`:

- `report_meta`, `artifact_ref` — provenance
- `signal_trace`, `stage_result`, `routing_stage_result`, `resolution_stage_result`, `aggregation_stage_result`, `proof_stage_result`, `trust_stage_result` — per-signal lifecycle
- `gate_result`, `gate_config`, `check_result` — routing internals
- `aggregate_forensics`, `gate_failure_rate`, `symbol_gate_failures`, `stage_summary` — aggregates
- `wilson_interval` — statistics
- `fate_changing_summary`, `failure_mode_entry` — failure analysis
- `chi_squared_result` — independence test
- `limitation`, `hash_chain` — trust and integrity

## License

MIT
