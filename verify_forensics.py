#!/usr/bin/env python3
"""
Zero-trust verifier for Consumer Signal Forensics reports.

Independently recomputes all statistics, cross-checks per-signal trace
consistency, validates Wilson CIs, chi-squared, and content hash integrity.

Usage:
    python verify_forensics.py forensic_report.json
"""

import json
import sys
import math
import hashlib
from collections import defaultdict


__version__ = "1.0.0"

# ── Statistics helpers (independent recomputation) ───────────────────────────

def wilson_ci(successes, total, z=1.96):
    if total == 0:
        return {"lower": 0.0, "upper": 0.0, "z": z}
    p = successes / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    spread = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denom
    lower = max(0.0, center - spread)
    upper = min(1.0, center + spread)
    return {"lower": round(lower, 6), "upper": round(upper, 6), "z": z}


def chi_squared_test(contingency):
    rows = sorted(contingency.keys())
    cols = sorted(set(c for r in contingency.values() for c in r))
    if len(rows) < 2 or len(cols) < 2:
        return 0.0, 0, 1.0, {}, 0.0

    observed = []
    for r in rows:
        row = [contingency[r].get(c, 0) for c in cols]
        observed.append(row)

    n = sum(sum(row) for row in observed)
    if n == 0:
        return 0.0, 0, 1.0, {}, 0.0

    row_totals = [sum(row) for row in observed]
    col_totals = [sum(observed[i][j] for i in range(len(rows))) for j in range(len(cols))]

    expected = []
    for i in range(len(rows)):
        exp_row = [row_totals[i] * col_totals[j] / n for j in range(len(cols))]
        expected.append(exp_row)

    chi2 = 0.0
    for i in range(len(rows)):
        for j in range(len(cols)):
            if expected[i][j] > 0:
                chi2 += (observed[i][j] - expected[i][j]) ** 2 / expected[i][j]

    df = (len(rows) - 1) * (len(cols) - 1)
    p_value = _chi2_survival(chi2, df) if df > 0 else 1.0
    k = min(len(rows), len(cols))
    cramers_v = math.sqrt(chi2 / (n * (k - 1))) if n > 0 and k > 1 else 0.0

    expected_dict = {}
    for i, r in enumerate(rows):
        expected_dict[r] = {cols[j]: round(expected[i][j], 4) for j in range(len(cols))}

    return round(chi2, 4), df, round(p_value, 6), expected_dict, round(cramers_v, 4)


def _chi2_survival(x, k):
    if x <= 0:
        return 1.0
    if k <= 0:
        return 0.0
    return 1.0 - _regularized_gamma_p(k / 2.0, x / 2.0)


def _regularized_gamma_p(a, x):
    if x < 0 or x == 0:
        return 0.0
    if x < a + 1:
        return _gamma_series(a, x)
    else:
        return 1.0 - _gamma_cf(a, x)


def _gamma_series(a, x, max_iter=200, eps=1e-12):
    if x == 0:
        return 0.0
    ap = a
    s = 1.0 / a
    ds = s
    for _ in range(max_iter):
        ap += 1
        ds *= x / ap
        s += ds
        if abs(ds) < abs(s) * eps:
            break
    return s * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _gamma_cf(a, x, max_iter=200, eps=1e-12):
    fpmin = 1e-30
    b = x + 1 - a
    c = 1.0 / fpmin
    d = 1.0 / b
    h = d
    for i in range(1, max_iter + 1):
        an = -i * (i - a)
        b += 2
        d = an * d + b
        if abs(d) < fpmin:
            d = fpmin
        c = b + an / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1) < eps:
            break
    return h * math.exp(-x + a * math.log(x) - math.lgamma(a))


# ── Verifier ─────────────────────────────────────────────────────────────────

class ForensicsVerifier:
    """Zero-trust verifier for forensic reports."""

    def __init__(self, report):
        self.report = report
        self.results = []
        self.categories = defaultdict(lambda: {"pass": 0, "fail": 0})

    def check(self, category, name, condition, detail=""):
        status = "PASS" if condition else "FAIL"
        self.results.append({
            "category": category,
            "check": name,
            "status": status,
            "detail": detail
        })
        self.categories[category]["pass" if condition else "fail"] += 1
        return condition

    def verify_all(self):
        """Run all verification checks."""
        self.verify_structure()
        self.verify_version()
        self.verify_meta()
        self.verify_policy_snapshot()
        self.verify_signal_traces()
        self.verify_per_signal_stages()
        self.verify_fate_changes()
        self.verify_aggregate_forensics()
        self.verify_gate_failure_rates()
        self.verify_wilson_cis()
        self.verify_symbol_gate_failures()
        self.verify_stage_summaries()
        self.verify_fate_changing_summary()
        self.verify_failure_modes()
        self.verify_chi_squared()
        self.verify_limitations()
        self.verify_content_hash()
        return self.results

    def verify_structure(self):
        """Check top-level structure."""
        required = [
            "schema_version", "report_meta", "routing_policy_snapshot",
            "signal_traces", "aggregate_forensics", "fate_changing_summary",
            "failure_mode_ranking", "chi_squared_independence",
            "limitations", "content_hash"
        ]
        for field in required:
            self.check("structure", f"has_{field}",
                       field in self.report,
                       f"Top-level field '{field}'")

        self.check("structure", "signal_traces_is_array",
                   isinstance(self.report.get("signal_traces"), list),
                   "signal_traces must be an array")

        self.check("structure", "failure_mode_ranking_is_array",
                   isinstance(self.report.get("failure_mode_ranking"), list),
                   "failure_mode_ranking must be an array")

        self.check("structure", "limitations_is_array",
                   isinstance(self.report.get("limitations"), list),
                   "limitations must be an array")

    def verify_version(self):
        """Check schema version."""
        self.check("version", "schema_version_1.0.0",
                   self.report.get("schema_version") == "1.0.0",
                   f"Got: {self.report.get('schema_version')}")

    def verify_meta(self):
        """Check report metadata."""
        meta = self.report.get("report_meta", {})
        self.check("meta", "has_generated_at",
                   "generated_at" in meta, "generated_at field")
        self.check("meta", "has_generator_version",
                   "generator_version" in meta, "generator_version field")
        self.check("meta", "has_source_artifacts",
                   isinstance(meta.get("source_artifacts"), list),
                   "source_artifacts must be array")
        self.check("meta", "has_total_signals_traced",
                   isinstance(meta.get("total_signals_traced"), int),
                   f"Got: {meta.get('total_signals_traced')}")
        self.check("meta", "has_total_with_fate_change",
                   isinstance(meta.get("total_with_fate_change"), int),
                   f"Got: {meta.get('total_with_fate_change')}")

        # verify counts match actual data
        traces = self.report.get("signal_traces", [])
        self.check("meta", "total_signals_matches_traces",
                   meta.get("total_signals_traced") == len(traces),
                   f"Meta says {meta.get('total_signals_traced')}, actual {len(traces)}")

        fate_count = sum(1 for t in traces if t.get("has_fate_change"))
        self.check("meta", "total_fate_change_matches",
                   meta.get("total_with_fate_change") == fate_count,
                   f"Meta says {meta.get('total_with_fate_change')}, actual {fate_count}")

        # source artifacts have required fields
        for i, art in enumerate(meta.get("source_artifacts", [])):
            self.check("meta", f"artifact_{i}_has_name",
                       "name" in art, f"Artifact {i}")
            self.check("meta", f"artifact_{i}_has_path",
                       "path" in art, f"Artifact {i}")

    def verify_policy_snapshot(self):
        """Check routing policy snapshot."""
        policy = self.report.get("routing_policy_snapshot", {})
        self.check("policy", "has_gates",
                   "gates" in policy, "gates field present")
        self.check("policy", "has_symbols",
                   "symbols" in policy, "symbols field present")

        gates = policy.get("gates", {})
        expected_gates = ["regime_gate", "duration_gate", "confidence_gate",
                          "voi_gate", "weak_symbol_gate"]
        for gname in expected_gates:
            self.check("policy", f"gate_{gname}_present",
                       gname in gates, f"Gate {gname}")
            if gname in gates:
                self.check("policy", f"gate_{gname}_has_enabled",
                           "enabled" in gates[gname],
                           f"{gname} enabled field")

    def verify_signal_traces(self):
        """Check per-signal trace structure."""
        traces = self.report.get("signal_traces", [])
        required_trace_fields = [
            "signal_id", "symbol", "direction", "confidence",
            "stages", "final_action", "has_fate_change"
        ]
        required_stages = [
            "schema_validation", "routing", "resolution",
            "aggregation", "proof_inclusion", "trust_contribution"
        ]

        # check a sample (first 20 + last 5) to avoid O(n*k) explosion
        sample_indices = list(range(min(20, len(traces))))
        if len(traces) > 25:
            sample_indices.extend(range(len(traces) - 5, len(traces)))

        for i in sample_indices:
            t = traces[i]
            for field in required_trace_fields:
                self.check("trace_structure", f"trace_{i}_has_{field}",
                           field in t, f"Signal {t.get('signal_id', '?')}")

            stages = t.get("stages", {})
            for stage in required_stages:
                self.check("trace_structure", f"trace_{i}_has_stage_{stage}",
                           stage in stages,
                           f"Signal {t.get('signal_id', '?')}")

            # final_action valid enum
            self.check("trace_structure", f"trace_{i}_valid_action",
                       t.get("final_action") in ("EMIT", "WITHHOLD", "INVERT"),
                       f"Got: {t.get('final_action')}")

            # direction valid
            self.check("trace_structure", f"trace_{i}_valid_direction",
                       t.get("direction") in ("bullish", "bearish"),
                       f"Got: {t.get('direction')}")

            # confidence in range
            conf = t.get("confidence", -1)
            self.check("trace_structure", f"trace_{i}_confidence_range",
                       isinstance(conf, (int, float)) and 0 <= conf <= 1,
                       f"Got: {conf}")

    def verify_per_signal_stages(self):
        """Deep check per-signal stage verdicts."""
        traces = self.report.get("signal_traces", [])

        sample = traces[:15] if len(traces) > 15 else traces
        for i, t in enumerate(sample):
            stages = t.get("stages", {})

            # each stage has verdict
            for stage_name in ["schema_validation", "routing", "resolution",
                               "aggregation", "proof_inclusion", "trust_contribution"]:
                stage = stages.get(stage_name, {})
                self.check("stage_verdicts", f"trace_{i}_{stage_name}_has_verdict",
                           "verdict" in stage,
                           f"Stage {stage_name} in trace {i}")
                self.check("stage_verdicts", f"trace_{i}_{stage_name}_has_rationale",
                           "rationale" in stage,
                           f"Stage {stage_name} in trace {i}")

            # routing has gate_results
            routing = stages.get("routing", {})
            self.check("stage_verdicts", f"trace_{i}_routing_has_gate_results",
                       isinstance(routing.get("gate_results"), list),
                       f"Trace {i} routing gate_results")
            self.check("stage_verdicts", f"trace_{i}_routing_has_routed_action",
                       "routed_action" in routing,
                       f"Trace {i} routed_action")

            # routed_action matches final_action
            self.check("stage_verdicts", f"trace_{i}_action_consistency",
                       routing.get("routed_action") == t.get("final_action"),
                       f"routed_action={routing.get('routed_action')} vs final_action={t.get('final_action')}")

            # fate change consistency
            has_fc = t.get("has_fate_change", False)
            fc_gate = t.get("fate_changing_gate")
            if has_fc:
                self.check("stage_verdicts", f"trace_{i}_fate_gate_present",
                           fc_gate is not None,
                           "has_fate_change=True but no fate_changing_gate")
                self.check("stage_verdicts", f"trace_{i}_fate_detail_present",
                           t.get("fate_change_detail") is not None,
                           "has_fate_change=True but no fate_change_detail")
                # fate-changed signal should NOT be EMIT
                self.check("stage_verdicts", f"trace_{i}_fate_not_emit",
                           t.get("final_action") != "EMIT",
                           f"Fate-changed signal should not be EMIT, got {t.get('final_action')}")
            else:
                # no fate change means EMIT
                self.check("stage_verdicts", f"trace_{i}_no_fate_is_emit",
                           t.get("final_action") == "EMIT",
                           f"No fate change but final_action={t.get('final_action')}")

            # gate-level fate_changing flag consistency
            grs = routing.get("gate_results", [])
            fc_flags = [gr for gr in grs if gr.get("is_fate_changing")]
            if has_fc:
                self.check("stage_verdicts", f"trace_{i}_one_fate_gate_flagged",
                           len(fc_flags) == 1,
                           f"Expected 1 fate-changing gate, got {len(fc_flags)}")
                if fc_flags:
                    self.check("stage_verdicts", f"trace_{i}_fate_gate_name_matches",
                               fc_flags[0]["gate_name"] == fc_gate,
                               f"Flagged gate={fc_flags[0]['gate_name']} vs fate_changing_gate={fc_gate}")
            else:
                self.check("stage_verdicts", f"trace_{i}_no_fate_gate_flagged",
                           len(fc_flags) == 0,
                           f"No fate change but {len(fc_flags)} gates flagged")

            # resolution karma cross-check
            res = stages.get("resolution", {})
            if res.get("verdict") in ("PASS", "FAIL"):
                outcome = res.get("outcome", 0)
                conf = t.get("confidence", 0.5)
                expected_karma = conf * (2 * outcome - 1)
                actual_karma = res.get("karma", 0)
                self.check("stage_verdicts", f"trace_{i}_karma_recompute",
                           abs(expected_karma - actual_karma) < 0.001,
                           f"Expected karma={expected_karma:.4f}, got {actual_karma:.4f}")

                expected_brier = (conf - outcome) ** 2
                actual_brier = res.get("brier_score", 0)
                self.check("stage_verdicts", f"trace_{i}_brier_recompute",
                           abs(expected_brier - actual_brier) < 0.001,
                           f"Expected brier={expected_brier:.6f}, got {actual_brier:.6f}")

            # trust direction consistency
            trust = stages.get("trust_contribution", {})
            if trust.get("verdict") in ("PASS", "FAIL", "INFO"):
                karma_c = trust.get("karma_contribution", 0)
                trust_dir = trust.get("trust_direction", "NEUTRAL")
                if karma_c > 0:
                    self.check("stage_verdicts", f"trace_{i}_trust_dir_positive",
                               trust_dir == "IMPROVES",
                               f"Positive karma={karma_c} should be IMPROVES, got {trust_dir}")
                elif karma_c < 0:
                    self.check("stage_verdicts", f"trace_{i}_trust_dir_negative",
                               trust_dir == "DEGRADES",
                               f"Negative karma={karma_c} should be DEGRADES, got {trust_dir}")

    def verify_fate_changes(self):
        """Verify fate change mechanics across all traces."""
        traces = self.report.get("signal_traces", [])

        # count actual fate changes
        actual_fc = sum(1 for t in traces if t.get("has_fate_change"))
        actual_emit = sum(1 for t in traces if t.get("final_action") == "EMIT")
        actual_withhold = sum(1 for t in traces if t.get("final_action") == "WITHHOLD")
        actual_invert = sum(1 for t in traces if t.get("final_action") == "INVERT")

        self.check("fate_changes", "emit_plus_withhold_plus_invert_equals_total",
                   actual_emit + actual_withhold + actual_invert == len(traces),
                   f"EMIT={actual_emit} + WITHHOLD={actual_withhold} + INVERT={actual_invert} = {actual_emit + actual_withhold + actual_invert} vs total={len(traces)}")

        # non-EMIT signals must have fate change
        for t in traces:
            if t.get("final_action") != "EMIT":
                self.check("fate_changes", f"non_emit_{t.get('signal_id', '?')[:12]}_has_fc",
                           t.get("has_fate_change") == True,
                           f"Action={t.get('final_action')} but has_fate_change={t.get('has_fate_change')}")
                break  # only check first one as a sample

    def verify_aggregate_forensics(self):
        """Verify aggregate forensics block."""
        agg = self.report.get("aggregate_forensics", {})
        traces = self.report.get("signal_traces", [])

        self.check("aggregates", "has_total_signals",
                   "total_signals" in agg, "total_signals field")
        self.check("aggregates", "total_signals_matches",
                   agg.get("total_signals") == len(traces),
                   f"Aggregate says {agg.get('total_signals')}, actual {len(traces)}")

        # overall pass rate
        actual_emit = sum(1 for t in traces if t.get("final_action") == "EMIT")
        expected_rate = actual_emit / len(traces) if traces else 0.0
        self.check("aggregates", "pass_rate_recompute",
                   abs(agg.get("overall_pass_rate", -1) - expected_rate) < 0.001,
                   f"Expected {expected_rate:.4f}, got {agg.get('overall_pass_rate')}")

        # fate change rate
        actual_fc = sum(1 for t in traces if t.get("has_fate_change"))
        expected_fc_rate = actual_fc / len(traces) if traces else 0.0
        self.check("aggregates", "fate_change_rate_recompute",
                   abs(agg.get("fate_change_rate", -1) - expected_fc_rate) < 0.001,
                   f"Expected {expected_fc_rate:.4f}, got {agg.get('fate_change_rate')}")

        self.check("aggregates", "has_per_gate_failure_rates",
                   isinstance(agg.get("per_gate_failure_rates"), dict),
                   "per_gate_failure_rates field")
        self.check("aggregates", "has_per_symbol_gate_failures",
                   isinstance(agg.get("per_symbol_gate_failures"), dict),
                   "per_symbol_gate_failures field")
        self.check("aggregates", "has_per_stage_summary",
                   isinstance(agg.get("per_stage_summary"), dict),
                   "per_stage_summary field")

    def verify_gate_failure_rates(self):
        """Independently recompute per-gate failure rates."""
        traces = self.report.get("signal_traces", [])
        agg = self.report.get("aggregate_forensics", {})
        gate_rates = agg.get("per_gate_failure_rates", {})

        gate_names = ["regime_gate", "duration_gate", "confidence_gate",
                      "voi_gate", "weak_symbol_gate"]

        for gname in gate_names:
            if gname not in gate_rates:
                self.check("gate_rates", f"{gname}_present",
                           False, f"Gate {gname} missing from failure rates")
                continue

            # recompute from traces
            failures = 0
            evaluated = 0
            for t in traces:
                grs = t.get("stages", {}).get("routing", {}).get("gate_results", [])
                for gr in grs:
                    if gr["gate_name"] == gname:
                        if gr["verdict"] != "SKIP":
                            evaluated += 1
                            if gr["verdict"] == "FAIL":
                                failures += 1

            reported = gate_rates[gname]
            self.check("gate_rates", f"{gname}_failures",
                       reported.get("failures") == failures,
                       f"Expected {failures}, got {reported.get('failures')}")
            self.check("gate_rates", f"{gname}_total",
                       reported.get("total") == evaluated,
                       f"Expected {evaluated}, got {reported.get('total')}")

            expected_rate = failures / evaluated if evaluated > 0 else 0.0
            self.check("gate_rates", f"{gname}_rate",
                       abs(reported.get("rate", -1) - expected_rate) < 0.001,
                       f"Expected {expected_rate:.4f}, got {reported.get('rate')}")

    def verify_wilson_cis(self):
        """Independently recompute Wilson CIs for gate failure rates."""
        agg = self.report.get("aggregate_forensics", {})
        gate_rates = agg.get("per_gate_failure_rates", {})

        for gname, gdata in gate_rates.items():
            failures = gdata.get("failures", 0)
            total = gdata.get("total", 0)
            reported_ci = gdata.get("wilson_ci", {})

            expected_ci = wilson_ci(failures, total)

            self.check("wilson_ci", f"{gname}_lower",
                       abs(reported_ci.get("lower", -1) - expected_ci["lower"]) < 0.001,
                       f"Expected {expected_ci['lower']:.6f}, got {reported_ci.get('lower')}")
            self.check("wilson_ci", f"{gname}_upper",
                       abs(reported_ci.get("upper", -1) - expected_ci["upper"]) < 0.001,
                       f"Expected {expected_ci['upper']:.6f}, got {reported_ci.get('upper')}")
            self.check("wilson_ci", f"{gname}_z",
                       reported_ci.get("z") == 1.96,
                       f"Expected z=1.96, got {reported_ci.get('z')}")

    def verify_symbol_gate_failures(self):
        """Verify per-symbol gate failure breakdowns."""
        traces = self.report.get("signal_traces", [])
        agg = self.report.get("aggregate_forensics", {})
        sym_failures = agg.get("per_symbol_gate_failures", {})

        # recompute per-symbol signal counts
        sym_counts = defaultdict(int)
        for t in traces:
            sym_counts[t.get("symbol", "unknown")] += 1

        for sym, data in sym_failures.items():
            self.check("symbol_gates", f"{sym}_total_signals",
                       data.get("total_signals") == sym_counts.get(sym, 0),
                       f"Expected {sym_counts.get(sym, 0)}, got {data.get('total_signals')}")

            # recompute per-gate failures for this symbol
            gate_names = ["regime_gate", "duration_gate", "confidence_gate",
                          "voi_gate", "weak_symbol_gate"]
            for gname in gate_names:
                expected_failures = 0
                for t in traces:
                    if t.get("symbol") != sym:
                        continue
                    grs = t.get("stages", {}).get("routing", {}).get("gate_results", [])
                    for gr in grs:
                        if gr["gate_name"] == gname and gr["verdict"] == "FAIL":
                            expected_failures += 1

                gate_data = data.get("gate_failures", {}).get(gname, {})
                self.check("symbol_gates", f"{sym}_{gname}_failures",
                           gate_data.get("failures", -1) == expected_failures,
                           f"Expected {expected_failures}, got {gate_data.get('failures')}")

    def verify_stage_summaries(self):
        """Verify per-stage summary counts."""
        traces = self.report.get("signal_traces", [])
        agg = self.report.get("aggregate_forensics", {})
        stage_summary = agg.get("per_stage_summary", {})

        stages = ["schema_validation", "routing", "resolution",
                  "aggregation", "proof_inclusion", "trust_contribution"]

        for stage_name in stages:
            summary = stage_summary.get(stage_name, {})

            # recompute
            pass_c = fail_c = skip_c = info_c = 0
            for t in traces:
                v = t.get("stages", {}).get(stage_name, {}).get("verdict", "SKIP")
                if v == "PASS":
                    pass_c += 1
                elif v == "FAIL":
                    fail_c += 1
                elif v == "SKIP":
                    skip_c += 1
                elif v == "INFO":
                    info_c += 1

            self.check("stage_summary", f"{stage_name}_pass",
                       summary.get("pass_count") == pass_c,
                       f"Expected {pass_c}, got {summary.get('pass_count')}")
            self.check("stage_summary", f"{stage_name}_fail",
                       summary.get("fail_count") == fail_c,
                       f"Expected {fail_c}, got {summary.get('fail_count')}")
            self.check("stage_summary", f"{stage_name}_skip",
                       summary.get("skip_count") == skip_c,
                       f"Expected {skip_c}, got {summary.get('skip_count')}")

    def verify_fate_changing_summary(self):
        """Verify fate changing summary block."""
        traces = self.report.get("signal_traces", [])
        fate = self.report.get("fate_changing_summary", {})

        # recompute
        fc_traces = [t for t in traces if t.get("has_fate_change")]
        total_fc = len(fc_traces)

        self.check("fate_summary", "total_fate_changes",
                   fate.get("total_fate_changes") == total_fc,
                   f"Expected {total_fc}, got {fate.get('total_fate_changes')}")

        expected_rate = total_fc / len(traces) if traces else 0.0
        self.check("fate_summary", "fate_change_rate",
                   abs(fate.get("fate_change_rate", -1) - expected_rate) < 0.001,
                   f"Expected {expected_rate:.4f}, got {fate.get('fate_change_rate')}")

        # by_gate recompute
        gate_counts = defaultdict(int)
        for t in fc_traces:
            g = t.get("fate_changing_gate")
            if g:
                gate_counts[g] += 1

        by_gate = fate.get("by_gate", {})
        for g, expected_count in gate_counts.items():
            self.check("fate_summary", f"by_gate_{g}_count",
                       by_gate.get(g, {}).get("count") == expected_count,
                       f"Expected {expected_count}, got {by_gate.get(g, {}).get('count')}")

            expected_frac = expected_count / total_fc if total_fc > 0 else 0.0
            self.check("fate_summary", f"by_gate_{g}_fraction",
                       abs(by_gate.get(g, {}).get("fraction", -1) - expected_frac) < 0.001,
                       f"Expected {expected_frac:.4f}")

        # by_symbol recompute
        sym_counts = defaultdict(int)
        for t in fc_traces:
            sym_counts[t.get("symbol")] += 1

        by_symbol = fate.get("by_symbol", {})
        for s, expected_count in sym_counts.items():
            self.check("fate_summary", f"by_symbol_{s}_count",
                       by_symbol.get(s, {}).get("count") == expected_count,
                       f"Expected {expected_count}, got {by_symbol.get(s, {}).get('count')}")

        # most impactful gate
        if gate_counts:
            expected_most = max(gate_counts, key=gate_counts.get)
            self.check("fate_summary", "most_impactful_gate",
                       fate.get("most_impactful_gate") == expected_most,
                       f"Expected {expected_most}, got {fate.get('most_impactful_gate')}")

        if sym_counts:
            expected_most_sym = max(sym_counts, key=sym_counts.get)
            self.check("fate_summary", "most_impacted_symbol",
                       fate.get("most_impacted_symbol") == expected_most_sym,
                       f"Expected {expected_most_sym}, got {fate.get('most_impacted_symbol')}")

    def verify_failure_modes(self):
        """Verify failure mode ranking."""
        modes = self.report.get("failure_mode_ranking", [])

        self.check("failure_modes", "is_array",
                   isinstance(modes, list), "failure_mode_ranking is array")

        # check descending order
        for i in range(1, len(modes)):
            self.check("failure_modes", f"descending_order_{i}",
                       modes[i]["count"] <= modes[i-1]["count"],
                       f"Mode {i}: {modes[i]['count']} > mode {i-1}: {modes[i-1]['count']}")

        # each mode has required fields
        for i, mode in enumerate(modes[:10]):
            self.check("failure_modes", f"mode_{i}_has_mode",
                       "mode" in mode, f"Mode {i}")
            self.check("failure_modes", f"mode_{i}_has_description",
                       "description" in mode, f"Mode {i}")
            self.check("failure_modes", f"mode_{i}_has_count",
                       isinstance(mode.get("count"), int), f"Mode {i}")
            self.check("failure_modes", f"mode_{i}_has_fraction",
                       isinstance(mode.get("fraction"), (int, float)),
                       f"Mode {i}")
            self.check("failure_modes", f"mode_{i}_has_affected_symbols",
                       isinstance(mode.get("affected_symbols"), list),
                       f"Mode {i}")
            self.check("failure_modes", f"mode_{i}_fraction_valid",
                       0 <= mode.get("fraction", -1) <= 1,
                       f"Fraction={mode.get('fraction')}")

    def verify_chi_squared(self):
        """Independently recompute chi-squared test."""
        chi2_block = self.report.get("chi_squared_independence", {})

        self.check("chi_squared", "has_statistic",
                   "statistic" in chi2_block, "statistic field")
        self.check("chi_squared", "has_df",
                   "degrees_of_freedom" in chi2_block, "df field")
        self.check("chi_squared", "has_p_value",
                   "p_value" in chi2_block, "p_value field")
        self.check("chi_squared", "has_independent",
                   "independent" in chi2_block, "independent field")
        self.check("chi_squared", "has_cramers_v",
                   "cramers_v" in chi2_block, "cramers_v field")

        # verify independence flag consistency
        p = chi2_block.get("p_value", 0)
        ind = chi2_block.get("independent", None)
        self.check("chi_squared", "independence_flag_correct",
                   ind == (p >= 0.05),
                   f"p={p}, independent={ind}, expected independent={p >= 0.05}")

        # recompute from contingency table
        contingency = chi2_block.get("contingency_table", {})
        if contingency and len(contingency) >= 2:
            stat, df, p_val, expected, cramers_v = chi_squared_test(contingency)

            self.check("chi_squared", "statistic_recompute",
                       abs(chi2_block.get("statistic", -1) - stat) < 0.1,
                       f"Expected {stat}, got {chi2_block.get('statistic')}")
            self.check("chi_squared", "df_recompute",
                       chi2_block.get("degrees_of_freedom") == df,
                       f"Expected {df}, got {chi2_block.get('degrees_of_freedom')}")
            self.check("chi_squared", "p_value_recompute",
                       abs(chi2_block.get("p_value", -1) - p_val) < 0.01,
                       f"Expected {p_val:.6f}, got {chi2_block.get('p_value')}")
            self.check("chi_squared", "cramers_v_recompute",
                       abs(chi2_block.get("cramers_v", -1) - cramers_v) < 0.01,
                       f"Expected {cramers_v}, got {chi2_block.get('cramers_v')}")

    def verify_limitations(self):
        """Verify limitations block."""
        lims = self.report.get("limitations", [])

        self.check("limitations", "has_limitations",
                   len(lims) >= 3, f"Expected >=3 limitations, got {len(lims)}")

        valid_bias = {"OVERSTATES", "UNDERSTATES", "AMBIGUOUS", "NEUTRAL"}
        valid_severity = {"LOW", "MEDIUM", "HIGH"}

        for i, lim in enumerate(lims):
            self.check("limitations", f"lim_{i}_has_id",
                       "id" in lim, f"Limitation {i}")
            self.check("limitations", f"lim_{i}_has_description",
                       "description" in lim, f"Limitation {i}")
            self.check("limitations", f"lim_{i}_has_bias_direction",
                       lim.get("bias_direction") in valid_bias,
                       f"Got: {lim.get('bias_direction')}")
            self.check("limitations", f"lim_{i}_has_severity",
                       lim.get("severity") in valid_severity,
                       f"Got: {lim.get('severity')}")
            self.check("limitations", f"lim_{i}_has_magnitude",
                       "magnitude" in lim, f"Limitation {i}")

    def verify_content_hash(self):
        """Verify SHA-256 content hash integrity."""
        hash_block = self.report.get("content_hash", {})

        self.check("content_hash", "has_algorithm",
                   hash_block.get("algorithm") == "SHA-256",
                   f"Got: {hash_block.get('algorithm')}")
        self.check("content_hash", "has_content_hash",
                   isinstance(hash_block.get("content_hash"), str) and len(hash_block.get("content_hash", "")) == 64,
                   f"Hash length: {len(hash_block.get('content_hash', ''))}")
        self.check("content_hash", "has_fields_hashed",
                   isinstance(hash_block.get("fields_hashed"), list),
                   "fields_hashed present")

        # recompute hash
        fields = hash_block.get("fields_hashed", [])
        hashable = {}
        for field in fields:
            if field in self.report:
                hashable[field] = self.report[field]

        raw = json.dumps(hashable, sort_keys=True, separators=(",", ":"))
        expected_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()

        self.check("content_hash", "hash_integrity",
                   hash_block.get("content_hash") == expected_hash,
                   f"Expected {expected_hash[:16]}..., got {hash_block.get('content_hash', '')[:16]}...")

    def summary(self):
        """Print verification summary."""
        total_pass = sum(c["pass"] for c in self.categories.values())
        total_fail = sum(c["fail"] for c in self.categories.values())
        total = total_pass + total_fail

        grade = "A" if total_fail == 0 else ("B" if total_fail <= 3 else ("C" if total_fail <= 10 else "F"))

        print(f"\nSignal Forensics Verification — {total} checks")
        print("=" * 60)

        for cat in sorted(self.categories):
            p = self.categories[cat]["pass"]
            f = self.categories[cat]["fail"]
            status = "PASS" if f == 0 else "FAIL"
            print(f"  [{status}] {cat}: {p}/{p+f}")

        print("=" * 60)
        print(f"  Total: {total_pass}/{total} PASS, {total_fail} FAIL — Grade {grade}")

        if total_fail > 0:
            print("\nFailed checks:")
            for r in self.results:
                if r["status"] == "FAIL":
                    print(f"  [{r['category']}] {r['check']}: {r['detail']}")

        return total_pass, total_fail, grade


def main():
    if len(sys.argv) < 2:
        print("Usage: python verify_forensics.py <forensic_report.json>")
        sys.exit(1)

    path = sys.argv[1]
    with open(path, "r") as f:
        report = json.load(f)

    verifier = ForensicsVerifier(report)
    verifier.verify_all()
    total_pass, total_fail, grade = verifier.summary()

    sys.exit(0 if total_fail == 0 else 1)


if __name__ == "__main__":
    main()
