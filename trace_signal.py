#!/usr/bin/env python3
"""
Consumer Signal Forensics — Per-signal lifecycle tracer.

Traces each signal through 6 protocol stages:
  1. Schema validation — field presence, value ranges, enum compliance
  2. Routing — 5 sequential gates (regime, duration, confidence, VOI, weak symbol)
  3. Resolution — direction correctness, karma, Brier score
  4. Aggregation — reputation-weighted contribution (single-producer pass-through)
  5. Proof inclusion — rolling window membership, freshness grading
  6. Trust contribution — accuracy/karma/Brier impact direction

Identifies fate-changing gates and aggregates failure modes with Wilson CIs
and chi-squared independence tests.

Zero external dependencies. Consumer-side only.

Usage:
    python trace_signal.py --signals resolved_signals.json [--policy routing_policy.json] [--output forensic_report.json]
"""

import json
import hashlib
import math
import sys
import argparse
from datetime import datetime, timezone
from collections import defaultdict

__version__ = "1.0.0"

# ── Schema validation constants ──────────────────────────────────────────────

REQUIRED_SIGNAL_FIELDS = [
    "signal_id", "symbol", "direction", "confidence"
]
OPTIONAL_SIGNAL_FIELDS = [
    "signal_client_id", "horizon_hours", "timestamp", "regime",
    "regime_duration_days", "regime_confidence", "action", "decision",
    "proximity", "method", "quality", "start_price", "end_price",
    "pct_change", "actual_direction", "direction_correct", "outcome",
    "brier_score"
]
VALID_DIRECTIONS = {"bullish", "bearish"}
VALID_REGIMES = {"SYSTEMIC", "NEUTRAL", "DIVERGENCE", "EARNINGS", "UNKNOWN"}
VALID_ACTIONS = {"EXECUTE", "WITHHOLD", "INVERT"}
VALID_SYMBOLS = {"BTC", "ETH", "SOL", "LINK"}

# ── Default routing policy (matches b1e55ed producer) ────────────────────────

DEFAULT_POLICY = {
    "description": "Default routing policy based on b1e55ed producer configuration",
    "gates": {
        "regime_gate": {
            "enabled": True,
            "allowed_regimes": ["NEUTRAL"],
            "threshold": "NEUTRAL only"
        },
        "duration_gate": {
            "enabled": True,
            "default_min_days": 15,
            "threshold": 15
        },
        "confidence_gate": {
            "enabled": True,
            "default_min_confidence": 0.30,
            "threshold": 0.30
        },
        "voi_gate": {
            "enabled": False,
            "min_voi": 0.0,
            "threshold": 0.0
        },
        "weak_symbol_gate": {
            "enabled": True,
            "severity_threshold": "MODERATE",
            "threshold": "MODERATE"
        }
    },
    "symbols": {
        "BTC": {"weak_symbol_policy": "NONE", "accuracy": 0.5586},
        "ETH": {"weak_symbol_policy": "NONE", "accuracy": 0.5466},
        "SOL": {
            "weak_symbol_policy": "INVERT",
            "weakness_severity": "SEVERE",
            "weakness_score": 0.6979,
            "inversion_justified": True,
            "inversion_p_value": 0.0001,
            "accuracy": 0.4714
        },
        "LINK": {"weak_symbol_policy": "NONE", "accuracy": 0.5231}
    }
}


# ── Statistics helpers ───────────────────────────────────────────────────────

def wilson_ci(successes, total, z=1.96):
    """Wilson score confidence interval for a binomial proportion."""
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
    """
    Chi-squared test of independence on a contingency table.
    contingency: dict of {row_label: {col_label: count}}
    Returns: statistic, df, p_value, expected table, cramers_v
    """
    rows = sorted(contingency.keys())
    cols = sorted(set(c for r in contingency.values() for c in r))

    if len(rows) < 2 or len(cols) < 2:
        return 0.0, 0, 1.0, {}, 0.0

    # build observed matrix
    observed = []
    for r in rows:
        row = [contingency[r].get(c, 0) for c in cols]
        observed.append(row)

    n = sum(sum(row) for row in observed)
    if n == 0:
        return 0.0, 0, 1.0, {}, 0.0

    row_totals = [sum(row) for row in observed]
    col_totals = [sum(observed[i][j] for i in range(len(rows))) for j in range(len(cols))]

    # compute expected
    expected = []
    for i in range(len(rows)):
        exp_row = []
        for j in range(len(cols)):
            e = row_totals[i] * col_totals[j] / n
            exp_row.append(e)
        expected.append(exp_row)

    # chi-squared statistic
    chi2 = 0.0
    for i in range(len(rows)):
        for j in range(len(cols)):
            if expected[i][j] > 0:
                chi2 += (observed[i][j] - expected[i][j]) ** 2 / expected[i][j]

    df = (len(rows) - 1) * (len(cols) - 1)
    p_value = _chi2_survival(chi2, df) if df > 0 else 1.0

    # Cramer's V
    k = min(len(rows), len(cols))
    cramers_v = math.sqrt(chi2 / (n * (k - 1))) if n > 0 and k > 1 else 0.0

    # format expected table
    expected_dict = {}
    for i, r in enumerate(rows):
        expected_dict[r] = {}
        for j, c in enumerate(cols):
            expected_dict[r][c] = round(expected[i][j], 4)

    return round(chi2, 4), df, round(p_value, 6), expected_dict, round(cramers_v, 4)


def _chi2_survival(x, k):
    """
    Survival function P(X > x) for chi-squared distribution with k degrees of freedom.
    Uses regularized incomplete gamma function via series expansion.
    """
    if x <= 0:
        return 1.0
    if k <= 0:
        return 0.0
    return 1.0 - _regularized_gamma_p(k / 2.0, x / 2.0)


def _regularized_gamma_p(a, x):
    """Regularized lower incomplete gamma function P(a, x) via series expansion."""
    if x < 0:
        return 0.0
    if x == 0:
        return 0.0
    if x < a + 1:
        return _gamma_series(a, x)
    else:
        return 1.0 - _gamma_cf(a, x)


def _gamma_series(a, x, max_iter=200, eps=1e-12):
    """Series expansion for lower incomplete gamma."""
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
    """Continued fraction for upper incomplete gamma (Lentz's method)."""
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


# ── Stage 1: Schema Validation ──────────────────────────────────────────────

class SchemaValidator:
    """Validates signal fields against the canonical schema contract."""

    def trace(self, signal):
        checks = []
        all_pass = True

        # required fields
        for field in REQUIRED_SIGNAL_FIELDS:
            present = field in signal and signal[field] is not None
            checks.append({
                "check_name": f"required_field_{field}",
                "passed": present,
                "detail": f"{field} {'present' if present else 'MISSING'}"
            })
            if not present:
                all_pass = False

        # direction enum
        direction = signal.get("direction")
        dir_valid = direction in VALID_DIRECTIONS
        checks.append({
            "check_name": "direction_enum",
            "passed": dir_valid,
            "detail": f"direction='{direction}' {'valid' if dir_valid else 'invalid (expected bullish/bearish)'}"
        })
        if not dir_valid:
            all_pass = False

        # confidence range
        conf = signal.get("confidence")
        conf_valid = isinstance(conf, (int, float)) and 0.0 <= conf <= 1.0
        checks.append({
            "check_name": "confidence_range",
            "passed": conf_valid,
            "detail": f"confidence={conf} {'in [0,1]' if conf_valid else 'OUT OF RANGE'}"
        })
        if not conf_valid:
            all_pass = False

        # symbol known
        symbol = signal.get("symbol")
        sym_valid = symbol in VALID_SYMBOLS
        checks.append({
            "check_name": "symbol_known",
            "passed": sym_valid,
            "detail": f"symbol='{symbol}' {'known' if sym_valid else 'unknown'}"
        })
        if not sym_valid:
            all_pass = False

        # horizon_hours positive
        horizon = signal.get("horizon_hours")
        if horizon is not None:
            h_valid = isinstance(horizon, (int, float)) and horizon > 0
            checks.append({
                "check_name": "horizon_positive",
                "passed": h_valid,
                "detail": f"horizon_hours={horizon}"
            })
            if not h_valid:
                all_pass = False

        # regime enum
        regime = signal.get("regime")
        if regime is not None:
            r_valid = regime in VALID_REGIMES
            checks.append({
                "check_name": "regime_enum",
                "passed": r_valid,
                "detail": f"regime='{regime}' {'valid' if r_valid else 'unknown'}"
            })
            if not r_valid:
                all_pass = False

        verdict = "PASS" if all_pass else "FAIL"
        rationale = f"Schema validation: {sum(1 for c in checks if c['passed'])}/{len(checks)} checks passed"

        return {
            "verdict": verdict,
            "rationale": rationale,
            "checks": checks
        }


# ── Stage 2: Routing ────────────────────────────────────────────────────────

class RoutingTracer:
    """Traces signal through 5 sequential routing gates."""

    def __init__(self, policy):
        self.policy = policy
        self.gates_config = policy.get("gates", {})
        self.symbols_config = policy.get("symbols", {})

    def trace(self, signal):
        gate_results = []
        routed_action = "EMIT"
        fate_changing_gate = None
        fate_change_detail = None

        symbol = signal.get("symbol", "")
        sym_config = self.symbols_config.get(symbol, {})

        # Gate 1: Regime
        regime_cfg = self.gates_config.get("regime_gate", {})
        if regime_cfg.get("enabled", False):
            regime = signal.get("regime", "UNKNOWN")
            allowed = regime_cfg.get("allowed_regimes", ["NEUTRAL"])
            passed = regime in allowed
            gr = {
                "gate_name": "regime_gate",
                "verdict": "PASS" if passed else "FAIL",
                "rationale": f"regime='{regime}' {'in' if passed else 'NOT in'} allowed={allowed}",
                "threshold": allowed,
                "actual": regime,
                "is_fate_changing": False
            }
            if not passed and routed_action == "EMIT":
                routed_action = "WITHHOLD"
                gr["is_fate_changing"] = True
                fate_changing_gate = "regime_gate"
                fate_change_detail = f"Regime '{regime}' not in allowed regimes {allowed}"
            gate_results.append(gr)
        else:
            gate_results.append({
                "gate_name": "regime_gate",
                "verdict": "SKIP",
                "rationale": "Gate disabled",
                "threshold": None,
                "actual": None,
                "is_fate_changing": False
            })

        # Gate 2: Duration
        dur_cfg = self.gates_config.get("duration_gate", {})
        if dur_cfg.get("enabled", False):
            min_days = sym_config.get("min_duration_days",
                        dur_cfg.get("default_min_days", 15))
            actual_days = signal.get("regime_duration_days")
            if actual_days is not None:
                passed = actual_days >= min_days
                gr = {
                    "gate_name": "duration_gate",
                    "verdict": "PASS" if passed else "FAIL",
                    "rationale": "duration=%sd %s threshold=%sd" % (actual_days, ">=" if passed else "<", min_days),
                    "threshold": min_days,
                    "actual": actual_days,
                    "is_fate_changing": False
                }
                if not passed and routed_action == "EMIT":
                    routed_action = "WITHHOLD"
                    gr["is_fate_changing"] = True
                    fate_changing_gate = "duration_gate"
                    fate_change_detail = f"Regime duration {actual_days}d < minimum {min_days}d"
            else:
                gr = {
                    "gate_name": "duration_gate",
                    "verdict": "SKIP",
                    "rationale": "regime_duration_days not available in signal",
                    "threshold": min_days,
                    "actual": None,
                    "is_fate_changing": False
                }
            gate_results.append(gr)
        else:
            gate_results.append({
                "gate_name": "duration_gate",
                "verdict": "SKIP",
                "rationale": "Gate disabled",
                "threshold": None,
                "actual": None,
                "is_fate_changing": False
            })

        # Gate 3: Confidence
        conf_cfg = self.gates_config.get("confidence_gate", {})
        if conf_cfg.get("enabled", False):
            min_conf = sym_config.get("min_confidence",
                        conf_cfg.get("default_min_confidence", 0.30))
            actual_conf = signal.get("confidence", 0)
            passed = actual_conf >= min_conf
            gr = {
                "gate_name": "confidence_gate",
                "verdict": "PASS" if passed else "FAIL",
                "rationale": "confidence=%.4f %s threshold=%s" % (actual_conf, ">=" if passed else "<", min_conf),
                "threshold": min_conf,
                "actual": actual_conf,
                "is_fate_changing": False
            }
            if not passed and routed_action == "EMIT":
                routed_action = "WITHHOLD"
                gr["is_fate_changing"] = True
                fate_changing_gate = "confidence_gate"
                fate_change_detail = f"Confidence {actual_conf:.4f} < minimum {min_conf}"
            gate_results.append(gr)
        else:
            gate_results.append({
                "gate_name": "confidence_gate",
                "verdict": "SKIP",
                "rationale": "Gate disabled",
                "threshold": None,
                "actual": None,
                "is_fate_changing": False
            })

        # Gate 4: VOI
        voi_cfg = self.gates_config.get("voi_gate", {})
        if voi_cfg.get("enabled", False):
            min_voi = voi_cfg.get("min_voi", 0.0)
            # compute VOI from signal data if available
            conf = signal.get("confidence", 0.5)
            sym_acc = sym_config.get("accuracy", 0.5)
            voi_value = conf * (2 * sym_acc - 1)
            passed = voi_value >= min_voi
            gr = {
                "gate_name": "voi_gate",
                "verdict": "PASS" if passed else "FAIL",
                "rationale": "VOI=%.4f (conf=%.4f * (2*acc_%s=%.4f - 1)) %s threshold=%s" % (voi_value, conf, symbol, sym_acc, ">=" if passed else "<", min_voi),
                "threshold": min_voi,
                "actual": round(voi_value, 6),
                "is_fate_changing": False
            }
            if not passed and routed_action == "EMIT":
                routed_action = "WITHHOLD"
                gr["is_fate_changing"] = True
                fate_changing_gate = "voi_gate"
                fate_change_detail = f"VOI {voi_value:.4f} < minimum {min_voi}"
            gate_results.append(gr)
        else:
            gate_results.append({
                "gate_name": "voi_gate",
                "verdict": "SKIP",
                "rationale": "Gate disabled",
                "threshold": None,
                "actual": None,
                "is_fate_changing": False
            })

        # Gate 5: Weak Symbol
        ws_cfg = self.gates_config.get("weak_symbol_gate", {})
        if ws_cfg.get("enabled", False):
            ws_policy = sym_config.get("weak_symbol_policy", "NONE")
            severity = sym_config.get("weakness_severity", "NONE")
            sev_threshold = ws_cfg.get("severity_threshold", "MODERATE")

            sev_order = {"NONE": 0, "MILD": 1, "MODERATE": 2, "SEVERE": 3}
            sev_val = sev_order.get(severity, 0)
            sev_thresh_val = sev_order.get(sev_threshold, 2)

            if ws_policy == "NONE" or sev_val < sev_thresh_val:
                gr = {
                    "gate_name": "weak_symbol_gate",
                    "verdict": "PASS",
                    "rationale": f"{symbol}: policy={ws_policy}, severity={severity} (below threshold {sev_threshold})",
                    "threshold": sev_threshold,
                    "actual": severity,
                    "is_fate_changing": False
                }
            elif ws_policy == "INVERT":
                justified = sym_config.get("inversion_justified", False)
                p_val = sym_config.get("inversion_p_value", 1.0)
                gr = {
                    "gate_name": "weak_symbol_gate",
                    "verdict": "FAIL",
                    "rationale": f"{symbol}: INVERT (severity={severity}, justified={justified}, p={p_val})",
                    "threshold": sev_threshold,
                    "actual": severity,
                    "is_fate_changing": False
                }
                if routed_action == "EMIT":
                    routed_action = "INVERT"
                    gr["is_fate_changing"] = True
                    fate_changing_gate = "weak_symbol_gate"
                    fate_change_detail = f"{symbol} weakness severity={severity}, policy=INVERT (p={p_val})"
            elif ws_policy == "EXCLUDE":
                gr = {
                    "gate_name": "weak_symbol_gate",
                    "verdict": "FAIL",
                    "rationale": f"{symbol}: EXCLUDE (severity={severity})",
                    "threshold": sev_threshold,
                    "actual": severity,
                    "is_fate_changing": False
                }
                if routed_action == "EMIT":
                    routed_action = "WITHHOLD"
                    gr["is_fate_changing"] = True
                    fate_changing_gate = "weak_symbol_gate"
                    fate_change_detail = f"{symbol} EXCLUDED due to weakness severity={severity}"
            else:
                gr = {
                    "gate_name": "weak_symbol_gate",
                    "verdict": "PASS",
                    "rationale": f"{symbol}: policy={ws_policy}, severity={severity}",
                    "threshold": sev_threshold,
                    "actual": severity,
                    "is_fate_changing": False
                }
            gate_results.append(gr)
        else:
            gate_results.append({
                "gate_name": "weak_symbol_gate",
                "verdict": "SKIP",
                "rationale": "Gate disabled",
                "threshold": None,
                "actual": None,
                "is_fate_changing": False
            })

        passed_count = sum(1 for g in gate_results if g["verdict"] == "PASS")
        failed_count = sum(1 for g in gate_results if g["verdict"] == "FAIL")
        skipped_count = sum(1 for g in gate_results if g["verdict"] == "SKIP")

        verdict = "PASS" if routed_action == "EMIT" else "FAIL"
        rationale = f"Routing: {passed_count} passed, {failed_count} failed, {skipped_count} skipped → {routed_action}"

        return {
            "verdict": verdict,
            "rationale": rationale,
            "gate_results": gate_results,
            "routed_action": routed_action,
            "gates_passed": passed_count,
            "gates_failed": failed_count,
            "gates_skipped": skipped_count
        }, fate_changing_gate, fate_change_detail


# ── Stage 3: Resolution ─────────────────────────────────────────────────────

class ResolutionTracer:
    """Traces signal resolution outcome."""

    def trace(self, signal):
        has_outcome = "outcome" in signal and signal["outcome"] is not None

        if not has_outcome:
            return {
                "verdict": "SKIP",
                "rationale": "No resolution data available (unresolved signal)"
            }

        outcome = signal["outcome"]
        direction_correct = signal.get("direction_correct", outcome == 1.0)
        confidence = signal.get("confidence", 0.5)
        brier = signal.get("brier_score", (confidence - outcome) ** 2)
        karma = confidence * (2 * outcome - 1)
        pct_change = signal.get("pct_change")
        start_price = signal.get("start_price")
        end_price = signal.get("end_price")

        verdict = "PASS" if direction_correct else "FAIL"
        rationale = (
            f"Direction {'correct' if direction_correct else 'incorrect'}: "
            f"predicted={signal.get('direction', '?')}, "
            f"actual={signal.get('actual_direction', '?')}, "
            f"karma={karma:+.4f}, brier={brier:.4f}"
        )

        result = {
            "verdict": verdict,
            "rationale": rationale,
            "direction_correct": direction_correct,
            "outcome": outcome,
            "brier_score": round(brier, 6),
            "karma": round(karma, 6)
        }

        if pct_change is not None:
            result["pct_change"] = pct_change
        if start_price is not None:
            result["start_price"] = start_price
        if end_price is not None:
            result["end_price"] = end_price

        return result


# ── Stage 4: Aggregation ────────────────────────────────────────────────────

class AggregationTracer:
    """Traces signal through aggregation (single-producer pass-through)."""

    def __init__(self, reputation_score=None):
        self.reputation_score = reputation_score

    def trace(self, signal):
        confidence = signal.get("confidence", 0.5)
        direction_sign = 1.0 if signal.get("direction") == "bullish" else -1.0

        rep = self.reputation_score if self.reputation_score is not None else 0.5
        contribution = rep * confidence * direction_sign

        return {
            "verdict": "INFO",
            "rationale": (
                f"Single-producer system: no multi-producer aggregation. "
                f"Reputation weight={rep:.4f}, contribution={contribution:+.4f}"
            ),
            "reputation_weight": round(rep, 4),
            "contribution_magnitude": round(abs(contribution), 6),
            "solo_producer": True
        }


# ── Stage 5: Proof Inclusion ────────────────────────────────────────────────

class ProofTracer:
    """Traces signal proof inclusion and freshness."""

    def __init__(self, proof_surface=None):
        self.proof_surface = proof_surface

    def trace(self, signal):
        has_outcome = "outcome" in signal and signal["outcome"] is not None

        if not has_outcome:
            return {
                "verdict": "SKIP",
                "rationale": "Unresolved signal — not yet eligible for proof inclusion",
                "included_in_proof": False,
                "window_membership": [],
                "freshness_grade": "EXPIRED"
            }

        # determine window membership based on signal timestamp
        timestamp = signal.get("timestamp", "")
        windows = self._compute_windows(timestamp)
        freshness = self._compute_freshness(timestamp)

        included = len(windows) > 0

        return {
            "verdict": "PASS" if included else "INFO",
            "rationale": (
                f"Signal {'included' if included else 'excluded'} from proof surface. "
                f"Windows: {windows}. Freshness: {freshness}"
            ),
            "included_in_proof": included,
            "window_membership": windows,
            "freshness_grade": freshness
        }

    def _compute_windows(self, timestamp_str):
        """Determine which rolling windows contain this signal."""
        if not timestamp_str:
            return ["all_time"]

        try:
            if "+" in timestamp_str or timestamp_str.endswith("Z"):
                ts = timestamp_str.replace("Z", "+00:00")
                sig_dt = datetime.fromisoformat(ts)
            else:
                sig_dt = datetime.fromisoformat(timestamp_str)
                sig_dt = sig_dt.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            age_days = (now - sig_dt).total_seconds() / 86400.0

            windows = ["all_time"]
            if age_days <= 30:
                windows.append("30d")
            if age_days <= 14:
                windows.append("14d")
            if age_days <= 7:
                windows.append("7d")
            return windows
        except (ValueError, TypeError):
            return ["all_time"]

    def _compute_freshness(self, timestamp_str):
        """Compute freshness grade based on signal age."""
        if not timestamp_str:
            return "EXPIRED"
        try:
            if "+" in timestamp_str or timestamp_str.endswith("Z"):
                ts = timestamp_str.replace("Z", "+00:00")
                sig_dt = datetime.fromisoformat(ts)
            else:
                sig_dt = datetime.fromisoformat(timestamp_str)
                sig_dt = sig_dt.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            age_hours = (now - sig_dt).total_seconds() / 3600.0
            staleness_threshold = 24.0

            if age_hours <= staleness_threshold:
                return "LIVE"
            elif age_hours <= 2 * staleness_threshold:
                return "RECENT"
            elif age_hours <= 4 * staleness_threshold:
                return "STALE"
            else:
                return "EXPIRED"
        except (ValueError, TypeError):
            return "EXPIRED"


# ── Stage 6: Trust Contribution ─────────────────────────────────────────────

class TrustTracer:
    """Traces signal's contribution to producer trust metrics."""

    def __init__(self, baseline_accuracy=0.5):
        self.baseline_accuracy = baseline_accuracy

    def trace(self, signal):
        has_outcome = "outcome" in signal and signal["outcome"] is not None

        if not has_outcome:
            return {
                "verdict": "SKIP",
                "rationale": "Unresolved signal — no trust impact yet"
            }

        outcome = signal["outcome"]
        confidence = signal.get("confidence", 0.5)
        direction_correct = signal.get("direction_correct", outcome == 1.0)

        karma = confidence * (2 * outcome - 1)
        brier = (confidence - outcome) ** 2

        # accuracy impact
        if direction_correct:
            acc_impact = "POSITIVE"
        else:
            acc_impact = "NEGATIVE"

        # trust direction: positive karma = improves trust
        if karma > 0:
            trust_dir = "IMPROVES"
        elif karma < 0:
            trust_dir = "DEGRADES"
        else:
            trust_dir = "NEUTRAL"

        brier_baseline = 0.25  # coin flip
        brier_better = brier < brier_baseline

        return {
            "verdict": "PASS" if trust_dir == "IMPROVES" else ("FAIL" if trust_dir == "DEGRADES" else "INFO"),
            "rationale": (
                f"Karma={karma:+.4f} ({trust_dir}), Brier={brier:.4f} "
                f"({'better' if brier_better else 'worse'} than baseline 0.25), "
                f"accuracy impact={acc_impact}"
            ),
            "accuracy_impact": acc_impact,
            "karma_contribution": round(karma, 6),
            "brier_contribution": round(brier, 6),
            "trust_direction": trust_dir
        }


# ── Forensics Orchestrator ──────────────────────────────────────────────────

class ForensicsRunner:
    """Orchestrates per-signal tracing and aggregate analysis."""

    def __init__(self, policy=None, reputation_score=None):
        self.policy = policy or DEFAULT_POLICY
        self.schema_validator = SchemaValidator()
        self.routing_tracer = RoutingTracer(self.policy)
        self.resolution_tracer = ResolutionTracer()
        self.aggregation_tracer = AggregationTracer(reputation_score)
        self.proof_tracer = ProofTracer()
        self.trust_tracer = TrustTracer()

    def trace_signal(self, signal):
        """Trace a single signal through all 6 stages."""
        # Stage 1: Schema
        schema_result = self.schema_validator.trace(signal)

        # Stage 2: Routing
        routing_result, fate_gate, fate_detail = self.routing_tracer.trace(signal)

        # Stage 3: Resolution
        resolution_result = self.resolution_tracer.trace(signal)

        # Stage 4: Aggregation
        aggregation_result = self.aggregation_tracer.trace(signal)

        # Stage 5: Proof
        proof_result = self.proof_tracer.trace(signal)

        # Stage 6: Trust
        trust_result = self.trust_tracer.trace(signal)

        # Determine final action
        final_action = routing_result["routed_action"]
        has_fate_change = fate_gate is not None

        trace = {
            "signal_id": signal.get("signal_id", "unknown"),
            "symbol": signal.get("symbol", "unknown"),
            "direction": signal.get("direction", "unknown"),
            "confidence": signal.get("confidence", 0),
            "stages": {
                "schema_validation": schema_result,
                "routing": routing_result,
                "resolution": resolution_result,
                "aggregation": aggregation_result,
                "proof_inclusion": proof_result,
                "trust_contribution": trust_result
            },
            "final_action": final_action,
            "has_fate_change": has_fate_change,
            "fate_changing_gate": fate_gate,
            "fate_change_detail": fate_detail
        }

        # optional fields
        if "signal_client_id" in signal:
            trace["signal_client_id"] = signal["signal_client_id"]
        if "horizon_hours" in signal:
            trace["horizon_hours"] = signal["horizon_hours"]
        if "timestamp" in signal:
            trace["timestamp"] = signal["timestamp"]
        if "regime" in signal:
            trace["regime"] = signal["regime"]
        if "regime_duration_days" in signal:
            trace["regime_duration_days"] = signal["regime_duration_days"]

        return trace

    def run(self, signals, source_artifacts=None):
        """Run forensics on a batch of signals and produce full report."""
        traces = []
        for sig in signals:
            traces.append(self.trace_signal(sig))

        # aggregate
        agg = self._compute_aggregates(traces)
        fate_summary = self._compute_fate_summary(traces)
        failure_modes = self._compute_failure_modes(traces, signals)
        chi2 = self._compute_chi_squared(traces)
        limitations = self._compute_limitations(traces, signals)

        # date range from signals
        timestamps = [s.get("timestamp", "") for s in signals if s.get("timestamp")]
        date_range = {}
        if timestamps:
            sorted_ts = sorted(timestamps)
            date_range = {"start": sorted_ts[0][:10], "end": sorted_ts[-1][:10]}

        report = {
            "schema_version": "1.0.0",
            "report_meta": {
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "generator_version": __version__,
                "source_artifacts": source_artifacts or [],
                "total_signals_traced": len(traces),
                "total_with_fate_change": sum(1 for t in traces if t["has_fate_change"]),
                "date_range": date_range
            },
            "routing_policy_snapshot": {
                "description": self.policy.get("description", ""),
                "gates": self.policy.get("gates", {}),
                "symbols": self.policy.get("symbols", {})
            },
            "signal_traces": traces,
            "aggregate_forensics": agg,
            "fate_changing_summary": fate_summary,
            "failure_mode_ranking": failure_modes,
            "chi_squared_independence": chi2,
            "limitations": limitations,
            "content_hash": {"algorithm": "SHA-256", "content_hash": "0" * 64,
                             "fields_hashed": ["report_meta", "signal_traces",
                                               "aggregate_forensics", "fate_changing_summary",
                                               "failure_mode_ranking", "chi_squared_independence"]}
        }

        # compute real content hash
        report["content_hash"]["content_hash"] = self._compute_hash(report)
        return report

    def _compute_aggregates(self, traces):
        """Compute aggregate forensics from all traces."""
        total = len(traces)
        if total == 0:
            return {
                "total_signals": 0,
                "total_fate_changes": 0,
                "fate_change_rate": 0.0,
                "overall_pass_rate": 0.0,
                "per_gate_failure_rates": {},
                "per_symbol_gate_failures": {},
                "per_stage_summary": {}
            }

        total_fate = sum(1 for t in traces if t["has_fate_change"])
        emitted = sum(1 for t in traces if t["final_action"] == "EMIT")

        # per-gate failure rates
        gate_names = ["regime_gate", "duration_gate", "confidence_gate", "voi_gate", "weak_symbol_gate"]
        gate_failures = {}
        for gname in gate_names:
            failures = 0
            evaluated = 0
            for t in traces:
                grs = t["stages"]["routing"].get("gate_results", [])
                for gr in grs:
                    if gr["gate_name"] == gname:
                        if gr["verdict"] != "SKIP":
                            evaluated += 1
                            if gr["verdict"] == "FAIL":
                                failures += 1
            rate = failures / evaluated if evaluated > 0 else 0.0
            gate_failures[gname] = {
                "gate_name": gname,
                "failures": failures,
                "total": evaluated,
                "rate": round(rate, 6),
                "wilson_ci": wilson_ci(failures, evaluated)
            }

        # per-symbol gate failures
        symbol_failures = {}
        symbols_seen = set()
        for t in traces:
            sym = t["symbol"]
            symbols_seen.add(sym)

        for sym in sorted(symbols_seen):
            sym_traces = [t for t in traces if t["symbol"] == sym]
            sym_total = len(sym_traces)
            gf = {}
            for gname in gate_names:
                failures = 0
                for t in sym_traces:
                    grs = t["stages"]["routing"].get("gate_results", [])
                    for gr in grs:
                        if gr["gate_name"] == gname and gr["verdict"] == "FAIL":
                            failures += 1
                rate = failures / sym_total if sym_total > 0 else 0.0
                gf[gname] = {"failures": failures, "rate": round(rate, 6)}

            sym_fate_changes = sum(1 for t in sym_traces if t["has_fate_change"])
            symbol_failures[sym] = {
                "symbol": sym,
                "total_signals": sym_total,
                "gate_failures": gf,
                "total_fate_changes": sym_fate_changes
            }

        # per-stage summary
        stages = ["schema_validation", "routing", "resolution",
                  "aggregation", "proof_inclusion", "trust_contribution"]
        stage_summary = {}
        for stage in stages:
            pass_c = fail_c = skip_c = info_c = 0
            for t in traces:
                v = t["stages"][stage].get("verdict", "SKIP")
                if v == "PASS":
                    pass_c += 1
                elif v == "FAIL":
                    fail_c += 1
                elif v == "SKIP":
                    skip_c += 1
                elif v == "INFO":
                    info_c += 1
            stage_summary[stage] = {
                "stage_name": stage,
                "pass_count": pass_c,
                "fail_count": fail_c,
                "skip_count": skip_c,
                "info_count": info_c
            }

        return {
            "total_signals": total,
            "total_fate_changes": total_fate,
            "fate_change_rate": round(total_fate / total, 6) if total > 0 else 0.0,
            "overall_pass_rate": round(emitted / total, 6) if total > 0 else 0.0,
            "per_gate_failure_rates": gate_failures,
            "per_symbol_gate_failures": symbol_failures,
            "per_stage_summary": stage_summary
        }

    def _compute_fate_summary(self, traces):
        """Summarize fate-changing gates."""
        total = len(traces)
        fate_traces = [t for t in traces if t["has_fate_change"]]
        total_fate = len(fate_traces)

        by_gate = defaultdict(lambda: {"count": 0, "result_action": ""})
        by_symbol = defaultdict(lambda: {"count": 0})

        for t in fate_traces:
            gate = t["fate_changing_gate"]
            by_gate[gate]["count"] += 1
            by_gate[gate]["result_action"] = t["final_action"]
            by_symbol[t["symbol"]]["count"] += 1

        # compute fractions
        by_gate_out = {}
        for g, v in by_gate.items():
            by_gate_out[g] = {
                "count": v["count"],
                "fraction": round(v["count"] / total_fate, 6) if total_fate > 0 else 0.0,
                "result_action": v["result_action"]
            }

        by_symbol_out = {}
        for s, v in by_symbol.items():
            by_symbol_out[s] = {
                "count": v["count"],
                "fraction": round(v["count"] / total_fate, 6) if total_fate > 0 else 0.0
            }

        most_gate = max(by_gate_out, key=lambda g: by_gate_out[g]["count"]) if by_gate_out else ""
        most_sym = max(by_symbol_out, key=lambda s: by_symbol_out[s]["count"]) if by_symbol_out else ""

        return {
            "total_fate_changes": total_fate,
            "fate_change_rate": round(total_fate / total, 6) if total > 0 else 0.0,
            "by_gate": by_gate_out,
            "by_symbol": by_symbol_out,
            "most_impactful_gate": most_gate,
            "most_impacted_symbol": most_sym
        }

    def _compute_failure_modes(self, traces, signals):
        """Rank failure modes by frequency."""
        mode_counts = defaultdict(lambda: {"count": 0, "symbols": set(), "example": ""})

        for t in traces:
            # Schema failures
            if t["stages"]["schema_validation"]["verdict"] == "FAIL":
                checks = t["stages"]["schema_validation"].get("checks", [])
                for c in checks:
                    if not c["passed"]:
                        mode = f"schema:{c['check_name']}"
                        mode_counts[mode]["count"] += 1
                        mode_counts[mode]["symbols"].add(t["symbol"])
                        if not mode_counts[mode]["example"]:
                            mode_counts[mode]["example"] = t["signal_id"]

            # Routing gate failures
            grs = t["stages"]["routing"].get("gate_results", [])
            for gr in grs:
                if gr["verdict"] == "FAIL":
                    mode = f"routing:{gr['gate_name']}"
                    mode_counts[mode]["count"] += 1
                    mode_counts[mode]["symbols"].add(t["symbol"])
                    if not mode_counts[mode]["example"]:
                        mode_counts[mode]["example"] = t["signal_id"]

            # Resolution failures
            if t["stages"]["resolution"]["verdict"] == "FAIL":
                mode = "resolution:direction_incorrect"
                mode_counts[mode]["count"] += 1
                mode_counts[mode]["symbols"].add(t["symbol"])
                if not mode_counts[mode]["example"]:
                    mode_counts[mode]["example"] = t["signal_id"]

            # Trust degradation
            if t["stages"]["trust_contribution"].get("trust_direction") == "DEGRADES":
                mode = "trust:degrades_producer"
                mode_counts[mode]["count"] += 1
                mode_counts[mode]["symbols"].add(t["symbol"])
                if not mode_counts[mode]["example"]:
                    mode_counts[mode]["example"] = t["signal_id"]

        # descriptions for known modes
        mode_descriptions = {
            "routing:regime_gate": "Signal withheld because current regime not in allowed list",
            "routing:duration_gate": "Signal withheld because regime duration below minimum threshold",
            "routing:confidence_gate": "Signal withheld because confidence below minimum threshold",
            "routing:voi_gate": "Signal withheld because expected value of information is negative",
            "routing:weak_symbol_gate": "Signal inverted or excluded due to weak symbol diagnosis",
            "resolution:direction_incorrect": "Signal direction prediction was wrong (outcome=0)",
            "trust:degrades_producer": "Signal degraded producer trust (negative karma)",
        }

        total = len(traces)
        ranked = sorted(mode_counts.items(), key=lambda x: x[1]["count"], reverse=True)

        result = []
        for mode, data in ranked:
            result.append({
                "mode": mode,
                "description": mode_descriptions.get(mode, f"Failure at {mode}"),
                "count": data["count"],
                "fraction": round(data["count"] / total, 6) if total > 0 else 0.0,
                "affected_symbols": sorted(data["symbols"]),
                "example_signal_id": data["example"]
            })

        return result

    def _compute_chi_squared(self, traces):
        """Chi-squared test for gate failure independence across symbols."""
        gate_names = ["regime_gate", "duration_gate", "confidence_gate", "voi_gate", "weak_symbol_gate"]

        # build contingency table: symbol -> gate -> failure count
        contingency = defaultdict(lambda: defaultdict(int))

        for t in traces:
            sym = t["symbol"]
            grs = t["stages"]["routing"].get("gate_results", [])
            for gr in grs:
                if gr["verdict"] == "FAIL":
                    contingency[sym][gr["gate_name"]] += 1

        # ensure all cells exist
        symbols = sorted(set(t["symbol"] for t in traces))
        for sym in symbols:
            for gname in gate_names:
                if gname not in contingency[sym]:
                    contingency[sym][gname] = 0

        # remove gates with zero failures everywhere (no information)
        active_gates = [g for g in gate_names if any(contingency[s][g] > 0 for s in symbols)]

        if len(symbols) < 2 or len(active_gates) < 2:
            return {
                "test_description": "Chi-squared test of independence: gate failures vs symbol",
                "statistic": 0.0,
                "degrees_of_freedom": 0,
                "p_value": 1.0,
                "independent": True,
                "contingency_table": {s: dict(contingency[s]) for s in symbols},
                "expected_table": {},
                "cramers_v": 0.0
            }

        # filter contingency to active gates only
        filtered = {}
        for sym in symbols:
            filtered[sym] = {g: contingency[sym][g] for g in active_gates}

        chi2, df, p_value, expected, cramers_v = chi_squared_test(filtered)

        return {
            "test_description": "Chi-squared test of independence: gate failures vs symbol",
            "statistic": chi2,
            "degrees_of_freedom": df,
            "p_value": p_value,
            "independent": p_value >= 0.05,
            "contingency_table": filtered,
            "expected_table": expected,
            "cramers_v": cramers_v
        }

    def _compute_limitations(self, traces, signals):
        """Generate honest limitations with bias direction and magnitude."""
        total = len(traces)
        resolved = sum(1 for t in traces if t["stages"]["resolution"]["verdict"] != "SKIP")
        unresolved = total - resolved

        unresolved_pct = (unresolved / total * 100) if total > 0 else 0.0

        limitations = [
            {
                "id": "L1",
                "description": (
                    "Routing gates are replayed from published policy defaults, not from "
                    "the actual gate decisions made at signal emission time. If the producer "
                    "changed policy mid-stream, traces may not match historical routing."
                ),
                "bias_direction": "AMBIGUOUS",
                "severity": "MEDIUM",
                "magnitude": "Unknown — depends on policy drift between emission and trace"
            },
            {
                "id": "L2",
                "description": (
                    "Aggregation stage assumes single-producer system. Multi-producer "
                    "consumers would have different aggregation weights and consensus outcomes."
                ),
                "bias_direction": "NEUTRAL",
                "severity": "LOW",
                "magnitude": "No bias — single-producer is accurate for current b1e55ed deployment"
            },
            {
                "id": "L3",
                "description": (
                    "Proof inclusion uses current timestamp for window membership. "
                    "Signals near window boundaries may be classified differently than "
                    "they were at proof snapshot time."
                ),
                "bias_direction": "UNDERSTATES",
                "severity": "LOW",
                "magnitude": "Affects only boundary signals; all signals >30d old drop from 7d/14d/30d windows"
            },
            {
                "id": "L4",
                "description": (
                    "%d of %d signals (%.1f%%) lack resolution data. "
                    "These signals get SKIP verdicts at resolution, proof, and trust stages. "
                    "Aggregate failure rates are computed on the full set, not just resolved signals."
                ) % (unresolved, total, unresolved_pct),
                "bias_direction": "UNDERSTATES",
                "severity": "MEDIUM" if total > 0 and unresolved > total * 0.1 else "LOW",
                "magnitude": "%.1f%% of signals excluded from resolution-dependent analysis" % unresolved_pct
            },
            {
                "id": "L5",
                "description": (
                    "VOI gate uses historical per-symbol accuracy as a static estimate. "
                    "In practice, VOI should be computed from the current regime-duration cell, "
                    "which varies over time."
                ),
                "bias_direction": "OVERSTATES",
                "severity": "LOW",
                "magnitude": "VOI gate is disabled by default; only relevant if consumer enables it"
            },
            {
                "id": "L6",
                "description": (
                    "Chi-squared test assumes cell counts are independent observations. "
                    "Sequential signals from the same producer in the same regime may be "
                    "autocorrelated, inflating the test statistic."
                ),
                "bias_direction": "OVERSTATES",
                "severity": "MEDIUM",
                "magnitude": "Could inflate chi-squared by ~10-30% for highly correlated signal streams"
            }
        ]

        return limitations

    def _compute_hash(self, report):
        """Compute SHA-256 content hash with placeholder approach."""
        hashable = {
            "report_meta": report["report_meta"],
            "signal_traces": report["signal_traces"],
            "aggregate_forensics": report["aggregate_forensics"],
            "fate_changing_summary": report["fate_changing_summary"],
            "failure_mode_ranking": report["failure_mode_ranking"],
            "chi_squared_independence": report["chi_squared_independence"]
        }
        raw = json.dumps(hashable, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ── CLI ──────────────────────────────────────────────────────────────────────

def load_signals(path):
    """Load signals from a resolved_signals.json file."""
    with open(path, "r") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "signals" in data:
        return data["signals"]
    raise ValueError(f"Cannot parse signals from {path}")


def load_policy(path):
    """Load routing policy from JSON. Falls back to default if not provided."""
    if path is None:
        return DEFAULT_POLICY
    with open(path, "r") as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(
        description="Consumer Signal Forensics — trace signals through 6 protocol stages"
    )
    parser.add_argument(
        "--signals", required=True,
        help="Path to resolved_signals.json (or any signal array JSON)"
    )
    parser.add_argument(
        "--policy", default=None,
        help="Path to routing_policy.json (optional, uses defaults if omitted)"
    )
    parser.add_argument(
        "--output", default="forensic_report.json",
        help="Output path for the forensic report (default: forensic_report.json)"
    )
    parser.add_argument(
        "--limit", type=int, default=0,
        help="Limit number of signals to trace (0 = all)"
    )
    parser.add_argument(
        "--reputation-score", type=float, default=None,
        help="Producer reputation score for aggregation (0-1)"
    )
    args = parser.parse_args()

    signals = load_signals(args.signals)
    if args.limit > 0:
        signals = signals[:args.limit]

    policy = load_policy(args.policy)

    source_artifacts = [
        {"name": "resolved_signals", "path": args.signals,
         "description": f"Signal log with {len(signals)} signals"}
    ]
    if args.policy:
        source_artifacts.append(
            {"name": "routing_policy", "path": args.policy,
             "description": "Custom routing policy configuration"}
        )

    runner = ForensicsRunner(
        policy=policy,
        reputation_score=args.reputation_score
    )
    report = runner.run(signals, source_artifacts=source_artifacts)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    # summary to stdout
    meta = report["report_meta"]
    agg = report["aggregate_forensics"]
    fate = report["fate_changing_summary"]
    chi2 = report["chi_squared_independence"]

    print(f"Signal Forensics Report — {meta['generated_at']}")
    print(f"  Signals traced: {meta['total_signals_traced']}")
    print(f"  Fate changes:   {meta['total_with_fate_change']} ({fate['fate_change_rate']*100:.1f}%)")
    print(f"  Pass rate:      {agg['overall_pass_rate']*100:.1f}%")
    print()
    print("Per-gate failure rates:")
    for gname, gdata in agg["per_gate_failure_rates"].items():
        ci = gdata["wilson_ci"]
        print(f"  {gname}: {gdata['failures']}/{gdata['total']} ({gdata['rate']*100:.1f}%) "
              f"CI=[{ci['lower']*100:.1f}%, {ci['upper']*100:.1f}%]")
    print()
    print(f"Most impactful gate:  {fate['most_impactful_gate']}")
    print(f"Most impacted symbol: {fate['most_impacted_symbol']}")
    print()
    print(f"Chi-squared independence: χ²={chi2['statistic']:.2f}, "
          f"df={chi2['degrees_of_freedom']}, p={chi2['p_value']:.4f}, "
          f"V={chi2['cramers_v']:.4f} "
          f"({'independent' if chi2['independent'] else 'NOT independent'})")
    print()
    print(f"Report written to: {args.output}")


if __name__ == "__main__":
    main()
