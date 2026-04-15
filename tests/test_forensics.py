#!/usr/bin/env python3
"""Comprehensive tests for Consumer Signal Forensics."""

import json
import math
import os
import sys
import unittest
import tempfile
import hashlib
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from trace_signal import (
    SchemaValidator, RoutingTracer, ResolutionTracer, AggregationTracer,
    ProofTracer, TrustTracer, ForensicsRunner,
    wilson_ci, chi_squared_test, DEFAULT_POLICY,
    _chi2_survival, _regularized_gamma_p, _gamma_series, _gamma_cf,
    load_signals
)
from verify_forensics import ForensicsVerifier


# ── Test fixtures ────────────────────────────────────────────────────────────

def make_signal(**overrides):
    """Create a valid test signal with optional overrides."""
    base = {
        "signal_id": "test-BTC-001",
        "signal_client_id": "pf-BTC-12345",
        "symbol": "BTC",
        "direction": "bullish",
        "confidence": 0.65,
        "horizon_hours": 24,
        "timestamp": "2026-04-10T12:00:00+00:00",
        "regime": "NEUTRAL",
        "regime_duration_days": 20,
        "regime_confidence": 80,
        "action": "EXECUTE",
        "decision": "TRADE",
        "proximity": 0.8,
        "start_price": 70000.0,
        "end_price": 71000.0,
        "pct_change": 0.01429,
        "actual_direction": "bullish",
        "direction_correct": True,
        "outcome": 1.0,
        "brier_score": 0.1225
    }
    base.update(overrides)
    return base


def make_batch(n=100, mix=True):
    """Create a batch of signals with controlled properties."""
    signals = []
    symbols = ["BTC", "ETH", "SOL", "LINK"]
    regimes = ["NEUTRAL", "SYSTEMIC"]

    for i in range(n):
        sym = symbols[i % 4]
        regime = regimes[0] if i < n * 0.6 else regimes[1]
        duration = 20 if regime == "NEUTRAL" else 10
        correct = (i % 3) != 0  # 66% accuracy
        direction = "bullish" if i % 2 == 0 else "bearish"
        confidence = 0.3 + (i % 7) * 0.1
        if confidence > 1.0:
            confidence = 0.5

        outcome = 1.0 if correct else 0.0
        actual_dir = direction if correct else ("bearish" if direction == "bullish" else "bullish")

        signals.append(make_signal(
            signal_id=f"test-{sym}-{i:04d}",
            signal_client_id=f"pf-{sym}-{i}",
            symbol=sym,
            direction=direction,
            confidence=round(confidence, 4),
            regime=regime,
            regime_duration_days=duration,
            actual_direction=actual_dir,
            direction_correct=correct,
            outcome=outcome,
            brier_score=round((confidence - outcome) ** 2, 6),
            start_price=70000 + i,
            end_price=70000 + i + (100 if correct else -100),
            pct_change=round((100 if correct else -100) / (70000 + i), 6)
        ))
    return signals


# ── Schema Tests ─────────────────────────────────────────────────────────────

class TestSchemaStructure(unittest.TestCase):
    """Test JSON schema file structure."""

    def setUp(self):
        schema_path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                    "signal_forensics_schema.json")
        with open(schema_path) as f:
            self.schema = json.load(f)

    def test_has_schema_field(self):
        self.assertEqual(self.schema["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_has_id(self):
        self.assertIn("$id", self.schema)

    def test_has_title(self):
        self.assertIn("title", self.schema)

    def test_has_defs(self):
        self.assertIn("$defs", self.schema)

    def test_has_required_fields(self):
        required = self.schema["required"]
        expected = [
            "schema_version", "report_meta", "routing_policy_snapshot",
            "signal_traces", "aggregate_forensics", "fate_changing_summary",
            "failure_mode_ranking", "chi_squared_independence",
            "limitations", "content_hash"
        ]
        for field in expected:
            self.assertIn(field, required)

    def test_defs_count(self):
        # should have 15+ $defs
        self.assertGreaterEqual(len(self.schema["$defs"]), 15)

    def test_signal_trace_def(self):
        self.assertIn("signal_trace", self.schema["$defs"])
        trace_def = self.schema["$defs"]["signal_trace"]
        self.assertIn("stages", trace_def["properties"])

    def test_stage_result_def(self):
        self.assertIn("stage_result", self.schema["$defs"])

    def test_gate_result_def(self):
        self.assertIn("gate_result", self.schema["$defs"])

    def test_wilson_interval_def(self):
        self.assertIn("wilson_interval", self.schema["$defs"])

    def test_chi_squared_result_def(self):
        self.assertIn("chi_squared_result", self.schema["$defs"])

    def test_limitation_def(self):
        lim = self.schema["$defs"]["limitation"]
        self.assertIn("bias_direction", lim["properties"])

    def test_no_additional_top_level(self):
        self.assertFalse(self.schema.get("additionalProperties", True))


# ── Statistics Tests ─────────────────────────────────────────────────────────

class TestWilsonCI(unittest.TestCase):
    """Test Wilson score confidence interval."""

    def test_basic(self):
        ci = wilson_ci(50, 100)
        self.assertAlmostEqual(ci["lower"], 0.401, places=2)
        self.assertAlmostEqual(ci["upper"], 0.599, places=2)

    def test_zero_total(self):
        ci = wilson_ci(0, 0)
        self.assertEqual(ci["lower"], 0.0)
        self.assertEqual(ci["upper"], 0.0)

    def test_all_success(self):
        ci = wilson_ci(100, 100)
        self.assertAlmostEqual(ci["upper"], 1.0, places=3)
        self.assertGreater(ci["lower"], 0.95)

    def test_all_failure(self):
        ci = wilson_ci(0, 100)
        self.assertAlmostEqual(ci["lower"], 0.0, places=3)
        self.assertLess(ci["upper"], 0.05)

    def test_z_value(self):
        ci = wilson_ci(50, 100)
        self.assertEqual(ci["z"], 1.96)

    def test_small_sample(self):
        ci = wilson_ci(1, 3)
        self.assertGreater(ci["upper"], ci["lower"])
        self.assertGreater(ci["lower"], 0.0)
        self.assertLess(ci["upper"], 1.0)

    def test_large_sample(self):
        ci = wilson_ci(500, 1000)
        self.assertAlmostEqual(ci["lower"], 0.469, places=2)
        self.assertAlmostEqual(ci["upper"], 0.531, places=2)


class TestChiSquared(unittest.TestCase):
    """Test chi-squared independence test."""

    def test_independent(self):
        # uniform distribution = independent
        contingency = {
            "BTC": {"gate_a": 10, "gate_b": 10},
            "ETH": {"gate_a": 10, "gate_b": 10}
        }
        chi2, df, p, expected, v = chi_squared_test(contingency)
        self.assertEqual(df, 1)
        self.assertAlmostEqual(chi2, 0.0, places=2)
        self.assertGreater(p, 0.05)

    def test_not_independent(self):
        # highly skewed = dependent
        contingency = {
            "BTC": {"gate_a": 100, "gate_b": 0},
            "ETH": {"gate_a": 0, "gate_b": 100}
        }
        chi2, df, p, expected, v = chi_squared_test(contingency)
        self.assertGreater(chi2, 10)
        self.assertLess(p, 0.05)

    def test_single_row(self):
        contingency = {"BTC": {"gate_a": 10}}
        chi2, df, p, expected, v = chi_squared_test(contingency)
        self.assertEqual(df, 0)
        self.assertEqual(p, 1.0)

    def test_cramers_v(self):
        contingency = {
            "BTC": {"gate_a": 100, "gate_b": 0},
            "ETH": {"gate_a": 0, "gate_b": 100}
        }
        _, _, _, _, v = chi_squared_test(contingency)
        self.assertAlmostEqual(v, 1.0, places=1)

    def test_cramers_v_independent(self):
        contingency = {
            "BTC": {"gate_a": 50, "gate_b": 50},
            "ETH": {"gate_a": 50, "gate_b": 50}
        }
        _, _, _, _, v = chi_squared_test(contingency)
        self.assertAlmostEqual(v, 0.0, places=2)

    def test_three_by_three(self):
        contingency = {
            "BTC": {"g1": 10, "g2": 20, "g3": 30},
            "ETH": {"g1": 15, "g2": 25, "g3": 20},
            "SOL": {"g1": 20, "g2": 10, "g3": 30}
        }
        chi2, df, p, expected, v = chi_squared_test(contingency)
        self.assertEqual(df, 4)
        self.assertGreater(chi2, 0)

    def test_expected_table(self):
        contingency = {
            "BTC": {"g1": 10, "g2": 20},
            "ETH": {"g1": 30, "g2": 40}
        }
        _, _, _, expected, _ = chi_squared_test(contingency)
        self.assertIn("BTC", expected)
        self.assertIn("ETH", expected)


class TestChiSquaredSurvival(unittest.TestCase):
    """Test chi-squared survival function."""

    def test_zero(self):
        self.assertAlmostEqual(_chi2_survival(0, 1), 1.0, places=4)

    def test_large_x(self):
        p = _chi2_survival(100, 1)
        self.assertLess(p, 0.001)

    def test_known_value(self):
        # chi2=3.841 with df=1 should give p≈0.05
        p = _chi2_survival(3.841, 1)
        self.assertAlmostEqual(p, 0.05, places=2)

    def test_df_2(self):
        # chi2=5.991 with df=2 should give p≈0.05
        p = _chi2_survival(5.991, 2)
        self.assertAlmostEqual(p, 0.05, places=2)


# ── Schema Validator Tests ───────────────────────────────────────────────────

class TestSchemaValidator(unittest.TestCase):
    """Test the schema validation stage."""

    def setUp(self):
        self.validator = SchemaValidator()

    def test_valid_signal(self):
        result = self.validator.trace(make_signal())
        self.assertEqual(result["verdict"], "PASS")

    def test_missing_signal_id(self):
        sig = make_signal()
        del sig["signal_id"]
        result = self.validator.trace(sig)
        self.assertEqual(result["verdict"], "FAIL")

    def test_invalid_direction(self):
        sig = make_signal(direction="sideways")
        result = self.validator.trace(sig)
        self.assertEqual(result["verdict"], "FAIL")

    def test_confidence_out_of_range(self):
        sig = make_signal(confidence=1.5)
        result = self.validator.trace(sig)
        self.assertEqual(result["verdict"], "FAIL")

    def test_confidence_negative(self):
        sig = make_signal(confidence=-0.1)
        result = self.validator.trace(sig)
        self.assertEqual(result["verdict"], "FAIL")

    def test_unknown_symbol(self):
        sig = make_signal(symbol="DOGE")
        result = self.validator.trace(sig)
        self.assertEqual(result["verdict"], "FAIL")

    def test_checks_array(self):
        result = self.validator.trace(make_signal())
        self.assertIn("checks", result)
        self.assertIsInstance(result["checks"], list)
        self.assertTrue(all(c["passed"] for c in result["checks"]))

    def test_rationale_present(self):
        result = self.validator.trace(make_signal())
        self.assertIn("rationale", result)

    def test_negative_horizon(self):
        sig = make_signal(horizon_hours=-1)
        result = self.validator.trace(sig)
        self.assertEqual(result["verdict"], "FAIL")

    def test_invalid_regime(self):
        sig = make_signal(regime="BULLISH")
        result = self.validator.trace(sig)
        self.assertEqual(result["verdict"], "FAIL")


# ── Routing Tests ────────────────────────────────────────────────────────────

class TestRoutingTracer(unittest.TestCase):
    """Test routing gate tracing."""

    def setUp(self):
        self.tracer = RoutingTracer(DEFAULT_POLICY)

    def test_emit_in_neutral(self):
        sig = make_signal(regime="NEUTRAL", regime_duration_days=20, confidence=0.65)
        result, gate, detail = self.tracer.trace(sig)
        self.assertEqual(result["routed_action"], "EMIT")
        self.assertIsNone(gate)

    def test_withhold_in_systemic(self):
        sig = make_signal(regime="SYSTEMIC")
        result, gate, detail = self.tracer.trace(sig)
        self.assertEqual(result["routed_action"], "WITHHOLD")
        self.assertEqual(gate, "regime_gate")

    def test_withhold_low_duration(self):
        sig = make_signal(regime="NEUTRAL", regime_duration_days=10)
        result, gate, detail = self.tracer.trace(sig)
        self.assertEqual(result["routed_action"], "WITHHOLD")
        self.assertEqual(gate, "duration_gate")

    def test_withhold_low_confidence(self):
        sig = make_signal(regime="NEUTRAL", regime_duration_days=20, confidence=0.1)
        result, gate, detail = self.tracer.trace(sig)
        self.assertEqual(result["routed_action"], "WITHHOLD")
        self.assertEqual(gate, "confidence_gate")

    def test_invert_sol(self):
        sig = make_signal(symbol="SOL", regime="NEUTRAL", regime_duration_days=20, confidence=0.65)
        result, gate, detail = self.tracer.trace(sig)
        self.assertEqual(result["routed_action"], "INVERT")
        self.assertEqual(gate, "weak_symbol_gate")

    def test_five_gates_present(self):
        sig = make_signal()
        result, _, _ = self.tracer.trace(sig)
        self.assertEqual(len(result["gate_results"]), 5)

    def test_gate_result_structure(self):
        sig = make_signal()
        result, _, _ = self.tracer.trace(sig)
        for gr in result["gate_results"]:
            self.assertIn("gate_name", gr)
            self.assertIn("verdict", gr)
            self.assertIn("rationale", gr)
            self.assertIn("is_fate_changing", gr)

    def test_first_failing_gate_is_fate_changing(self):
        # SYSTEMIC fails regime gate first, even though duration (10d) would also fail
        sig = make_signal(regime="SYSTEMIC", regime_duration_days=10, confidence=0.1)
        result, gate, _ = self.tracer.trace(sig)
        self.assertEqual(gate, "regime_gate")
        # only one gate should be fate-changing
        fc_gates = [g for g in result["gate_results"] if g["is_fate_changing"]]
        self.assertEqual(len(fc_gates), 1)

    def test_gate_counts(self):
        sig = make_signal(regime="NEUTRAL", regime_duration_days=20, confidence=0.65)
        result, _, _ = self.tracer.trace(sig)
        self.assertEqual(result["gates_passed"] + result["gates_failed"] + result["gates_skipped"], 5)

    def test_voi_gate_disabled(self):
        sig = make_signal()
        result, _, _ = self.tracer.trace(sig)
        voi_result = [g for g in result["gate_results"] if g["gate_name"] == "voi_gate"][0]
        self.assertEqual(voi_result["verdict"], "SKIP")

    def test_btc_no_weak_symbol(self):
        sig = make_signal(symbol="BTC", regime="NEUTRAL", regime_duration_days=20, confidence=0.65)
        result, _, _ = self.tracer.trace(sig)
        ws_result = [g for g in result["gate_results"] if g["gate_name"] == "weak_symbol_gate"][0]
        self.assertEqual(ws_result["verdict"], "PASS")


# ── Resolution Tests ─────────────────────────────────────────────────────────

class TestResolutionTracer(unittest.TestCase):
    """Test resolution stage tracing."""

    def setUp(self):
        self.tracer = ResolutionTracer()

    def test_correct_direction(self):
        sig = make_signal(direction_correct=True, outcome=1.0)
        result = self.tracer.trace(sig)
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["direction_correct"])

    def test_incorrect_direction(self):
        sig = make_signal(direction_correct=False, outcome=0.0)
        result = self.tracer.trace(sig)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertFalse(result["direction_correct"])

    def test_karma_positive(self):
        sig = make_signal(confidence=0.7, outcome=1.0)
        result = self.tracer.trace(sig)
        self.assertGreater(result["karma"], 0)

    def test_karma_negative(self):
        sig = make_signal(confidence=0.7, outcome=0.0)
        result = self.tracer.trace(sig)
        self.assertLess(result["karma"], 0)

    def test_brier_score(self):
        sig = make_signal(confidence=0.8, outcome=1.0)
        del sig["brier_score"]  # remove pre-computed value so tracer computes fresh
        result = self.tracer.trace(sig)
        expected = (0.8 - 1.0) ** 2
        self.assertAlmostEqual(result["brier_score"], expected, places=4)

    def test_unresolved_skip(self):
        sig = make_signal()
        del sig["outcome"]
        result = self.tracer.trace(sig)
        self.assertEqual(result["verdict"], "SKIP")

    def test_prices_included(self):
        sig = make_signal(start_price=70000, end_price=71000)
        result = self.tracer.trace(sig)
        self.assertEqual(result["start_price"], 70000)
        self.assertEqual(result["end_price"], 71000)


# ── Aggregation Tests ────────────────────────────────────────────────────────

class TestAggregationTracer(unittest.TestCase):
    """Test aggregation stage tracing."""

    def setUp(self):
        self.tracer = AggregationTracer(reputation_score=0.65)

    def test_solo_producer(self):
        sig = make_signal()
        result = self.tracer.trace(sig)
        self.assertTrue(result["solo_producer"])
        self.assertEqual(result["verdict"], "INFO")

    def test_reputation_weight(self):
        sig = make_signal()
        result = self.tracer.trace(sig)
        self.assertEqual(result["reputation_weight"], 0.65)

    def test_contribution_positive(self):
        sig = make_signal(direction="bullish", confidence=0.8)
        result = self.tracer.trace(sig)
        self.assertGreater(result["contribution_magnitude"], 0)

    def test_default_reputation(self):
        tracer = AggregationTracer()
        sig = make_signal()
        result = tracer.trace(sig)
        self.assertEqual(result["reputation_weight"], 0.5)


# ── Proof Tests ──────────────────────────────────────────────────────────────

class TestProofTracer(unittest.TestCase):
    """Test proof inclusion tracing."""

    def setUp(self):
        self.tracer = ProofTracer()

    def test_resolved_included(self):
        sig = make_signal()
        result = self.tracer.trace(sig)
        self.assertIn("included_in_proof", result)
        self.assertTrue(result["included_in_proof"])

    def test_unresolved_excluded(self):
        sig = make_signal()
        del sig["outcome"]
        result = self.tracer.trace(sig)
        self.assertEqual(result["verdict"], "SKIP")
        self.assertFalse(result["included_in_proof"])

    def test_freshness_grade(self):
        sig = make_signal()
        result = self.tracer.trace(sig)
        self.assertIn(result["freshness_grade"], ["LIVE", "RECENT", "STALE", "EXPIRED"])

    def test_window_membership(self):
        sig = make_signal()
        result = self.tracer.trace(sig)
        self.assertIsInstance(result["window_membership"], list)
        self.assertIn("all_time", result["window_membership"])

    def test_old_signal_expired(self):
        sig = make_signal(timestamp="2025-01-01T00:00:00+00:00")
        result = self.tracer.trace(sig)
        self.assertEqual(result["freshness_grade"], "EXPIRED")


# ── Trust Tests ──────────────────────────────────────────────────────────────

class TestTrustTracer(unittest.TestCase):
    """Test trust contribution tracing."""

    def setUp(self):
        self.tracer = TrustTracer()

    def test_positive_karma_improves(self):
        sig = make_signal(confidence=0.7, outcome=1.0)
        result = self.tracer.trace(sig)
        self.assertEqual(result["trust_direction"], "IMPROVES")
        self.assertGreater(result["karma_contribution"], 0)

    def test_negative_karma_degrades(self):
        sig = make_signal(confidence=0.7, outcome=0.0)
        result = self.tracer.trace(sig)
        self.assertEqual(result["trust_direction"], "DEGRADES")
        self.assertLess(result["karma_contribution"], 0)

    def test_accuracy_impact(self):
        sig = make_signal(direction_correct=True, outcome=1.0)
        result = self.tracer.trace(sig)
        self.assertEqual(result["accuracy_impact"], "POSITIVE")

    def test_brier_contribution(self):
        sig = make_signal(confidence=0.6, outcome=1.0)
        result = self.tracer.trace(sig)
        expected = (0.6 - 1.0) ** 2
        self.assertAlmostEqual(result["brier_contribution"], expected, places=4)

    def test_unresolved_skip(self):
        sig = make_signal()
        del sig["outcome"]
        result = self.tracer.trace(sig)
        self.assertEqual(result["verdict"], "SKIP")


# ── ForensicsRunner Tests ───────────────────────────────────────────────────

class TestForensicsRunner(unittest.TestCase):
    """Test the forensics orchestrator."""

    def setUp(self):
        self.runner = ForensicsRunner()

    def test_trace_single_signal(self):
        trace = self.runner.trace_signal(make_signal())
        self.assertIn("signal_id", trace)
        self.assertIn("stages", trace)
        self.assertIn("final_action", trace)
        self.assertIn("has_fate_change", trace)

    def test_run_batch(self):
        signals = make_batch(20)
        report = self.runner.run(signals)
        self.assertEqual(report["schema_version"], "1.0.0")
        self.assertEqual(len(report["signal_traces"]), 20)

    def test_report_has_all_fields(self):
        report = self.runner.run(make_batch(10))
        required = [
            "schema_version", "report_meta", "routing_policy_snapshot",
            "signal_traces", "aggregate_forensics", "fate_changing_summary",
            "failure_mode_ranking", "chi_squared_independence",
            "limitations", "content_hash"
        ]
        for field in required:
            self.assertIn(field, report)

    def test_source_artifacts(self):
        arts = [{"name": "test", "path": "/test.json", "description": "test file"}]
        report = self.runner.run(make_batch(5), source_artifacts=arts)
        self.assertEqual(report["report_meta"]["source_artifacts"], arts)

    def test_content_hash(self):
        report = self.runner.run(make_batch(10))
        self.assertEqual(report["content_hash"]["algorithm"], "SHA-256")
        self.assertEqual(len(report["content_hash"]["content_hash"]), 64)
        self.assertNotEqual(report["content_hash"]["content_hash"], "0" * 64)

    def test_deterministic(self):
        signals = make_batch(10)
        r1 = self.runner.run(signals)
        r2 = self.runner.run(signals)
        # traces should be identical (ignoring generated_at)
        self.assertEqual(r1["signal_traces"], r2["signal_traces"])

    def test_empty_batch(self):
        report = self.runner.run([])
        self.assertEqual(report["report_meta"]["total_signals_traced"], 0)
        self.assertEqual(len(report["signal_traces"]), 0)

    def test_custom_policy(self):
        policy = {
            "description": "Custom",
            "gates": {
                "regime_gate": {"enabled": False},
                "duration_gate": {"enabled": False},
                "confidence_gate": {"enabled": False},
                "voi_gate": {"enabled": False},
                "weak_symbol_gate": {"enabled": False}
            },
            "symbols": {}
        }
        runner = ForensicsRunner(policy=policy)
        sig = make_signal(regime="SYSTEMIC", confidence=0.01)
        trace = runner.trace_signal(sig)
        self.assertEqual(trace["final_action"], "EMIT")

    def test_reputation_score_propagates(self):
        runner = ForensicsRunner(reputation_score=0.85)
        trace = runner.trace_signal(make_signal())
        self.assertEqual(trace["stages"]["aggregation"]["reputation_weight"], 0.85)


# ── Aggregate Forensics Tests ───────────────────────────────────────────────

class TestAggregateFoensics(unittest.TestCase):
    """Test aggregate forensics computation."""

    def test_pass_rate(self):
        signals = [
            make_signal(regime="NEUTRAL", regime_duration_days=20, confidence=0.5),
            make_signal(regime="SYSTEMIC"),
        ]
        runner = ForensicsRunner()
        report = runner.run(signals)
        agg = report["aggregate_forensics"]
        # first signal passes, second is withheld by regime gate
        self.assertEqual(agg["total_signals"], 2)

    def test_per_gate_failure_rates(self):
        runner = ForensicsRunner()
        signals = make_batch(50)
        report = runner.run(signals)
        rates = report["aggregate_forensics"]["per_gate_failure_rates"]
        self.assertIn("regime_gate", rates)
        self.assertIn("wilson_ci", rates["regime_gate"])

    def test_per_symbol_failures(self):
        runner = ForensicsRunner()
        signals = make_batch(40)
        report = runner.run(signals)
        sym_failures = report["aggregate_forensics"]["per_symbol_gate_failures"]
        # should have entries for BTC, ETH, SOL, LINK
        symbols = set(s["symbol"] for s in signals)
        for sym in symbols:
            self.assertIn(sym, sym_failures)

    def test_stage_summary(self):
        runner = ForensicsRunner()
        report = runner.run(make_batch(20))
        summary = report["aggregate_forensics"]["per_stage_summary"]
        for stage in ["schema_validation", "routing", "resolution",
                      "aggregation", "proof_inclusion", "trust_contribution"]:
            self.assertIn(stage, summary)
            self.assertIn("pass_count", summary[stage])
            self.assertIn("fail_count", summary[stage])


# ── Fate Summary Tests ───────────────────────────────────────────────────────

class TestFateSummary(unittest.TestCase):
    """Test fate changing summary."""

    def test_fate_by_gate(self):
        runner = ForensicsRunner()
        signals = make_batch(50)
        report = runner.run(signals)
        fate = report["fate_changing_summary"]
        self.assertIn("by_gate", fate)
        self.assertIn("by_symbol", fate)

    def test_most_impactful_gate(self):
        runner = ForensicsRunner()
        signals = make_batch(100)
        report = runner.run(signals)
        fate = report["fate_changing_summary"]
        self.assertIsInstance(fate["most_impactful_gate"], str)

    def test_fractions_sum_to_one(self):
        runner = ForensicsRunner()
        signals = make_batch(100)
        report = runner.run(signals)
        fate = report["fate_changing_summary"]
        if fate["total_fate_changes"] > 0:
            gate_sum = sum(v["fraction"] for v in fate["by_gate"].values())
            self.assertAlmostEqual(gate_sum, 1.0, places=3)


# ── Failure Modes Tests ──────────────────────────────────────────────────────

class TestFailureModes(unittest.TestCase):
    """Test failure mode ranking."""

    def test_ranked_by_frequency(self):
        runner = ForensicsRunner()
        signals = make_batch(100)
        report = runner.run(signals)
        modes = report["failure_mode_ranking"]
        for i in range(1, len(modes)):
            self.assertGreaterEqual(modes[i-1]["count"], modes[i]["count"])

    def test_mode_structure(self):
        runner = ForensicsRunner()
        signals = make_batch(50)
        report = runner.run(signals)
        for mode in report["failure_mode_ranking"]:
            self.assertIn("mode", mode)
            self.assertIn("description", mode)
            self.assertIn("count", mode)
            self.assertIn("fraction", mode)
            self.assertIn("affected_symbols", mode)

    def test_regime_gate_failure_mode(self):
        # signals in SYSTEMIC should produce regime_gate failure mode
        signals = [make_signal(regime="SYSTEMIC") for _ in range(10)]
        runner = ForensicsRunner()
        report = runner.run(signals)
        modes = report["failure_mode_ranking"]
        mode_names = [m["mode"] for m in modes]
        self.assertIn("routing:regime_gate", mode_names)


# ── Chi-Squared Tests ────────────────────────────────────────────────────────

class TestChiSquaredReport(unittest.TestCase):
    """Test chi-squared in full report."""

    def test_chi_squared_present(self):
        runner = ForensicsRunner()
        report = runner.run(make_batch(100))
        chi2 = report["chi_squared_independence"]
        self.assertIn("statistic", chi2)
        self.assertIn("degrees_of_freedom", chi2)
        self.assertIn("p_value", chi2)
        self.assertIn("independent", chi2)
        self.assertIn("cramers_v", chi2)

    def test_contingency_table(self):
        runner = ForensicsRunner()
        report = runner.run(make_batch(100))
        chi2 = report["chi_squared_independence"]
        self.assertIn("contingency_table", chi2)
        self.assertIn("expected_table", chi2)

    def test_independence_flag(self):
        runner = ForensicsRunner()
        report = runner.run(make_batch(100))
        chi2 = report["chi_squared_independence"]
        self.assertEqual(chi2["independent"], chi2["p_value"] >= 0.05)


# ── Limitations Tests ────────────────────────────────────────────────────────

class TestLimitations(unittest.TestCase):
    """Test limitations block."""

    def test_has_limitations(self):
        runner = ForensicsRunner()
        report = runner.run(make_batch(10))
        self.assertGreaterEqual(len(report["limitations"]), 3)

    def test_limitation_structure(self):
        runner = ForensicsRunner()
        report = runner.run(make_batch(10))
        for lim in report["limitations"]:
            self.assertIn("id", lim)
            self.assertIn("description", lim)
            self.assertIn("bias_direction", lim)
            self.assertIn("severity", lim)
            self.assertIn("magnitude", lim)

    def test_valid_bias_directions(self):
        runner = ForensicsRunner()
        report = runner.run(make_batch(10))
        valid = {"OVERSTATES", "UNDERSTATES", "AMBIGUOUS", "NEUTRAL"}
        for lim in report["limitations"]:
            self.assertIn(lim["bias_direction"], valid)


# ── Verifier Tests ───────────────────────────────────────────────────────────

class TestVerifier(unittest.TestCase):
    """Test the zero-trust verifier."""

    def setUp(self):
        runner = ForensicsRunner()
        self.report = runner.run(make_batch(50))

    def test_all_pass(self):
        verifier = ForensicsVerifier(self.report)
        results = verifier.verify_all()
        failures = [r for r in results if r["status"] == "FAIL"]
        self.assertEqual(len(failures), 0, f"Failures: {failures}")

    def test_category_coverage(self):
        verifier = ForensicsVerifier(self.report)
        verifier.verify_all()
        expected_categories = [
            "structure", "version", "meta", "policy",
            "trace_structure", "stage_verdicts", "fate_changes",
            "aggregates", "gate_rates", "wilson_ci",
            "symbol_gates", "stage_summary", "fate_summary",
            "failure_modes", "chi_squared", "limitations",
            "content_hash"
        ]
        for cat in expected_categories:
            self.assertIn(cat, verifier.categories,
                          f"Missing category: {cat}")

    def test_detect_tampered_hash(self):
        report = json.loads(json.dumps(self.report))
        report["content_hash"]["content_hash"] = "a" * 64
        verifier = ForensicsVerifier(report)
        verifier.verify_all()
        hash_results = [r for r in verifier.results
                        if r["category"] == "content_hash" and r["check"] == "hash_integrity"]
        self.assertEqual(hash_results[0]["status"], "FAIL")

    def test_detect_wrong_count(self):
        report = json.loads(json.dumps(self.report))
        report["report_meta"]["total_signals_traced"] = 999
        verifier = ForensicsVerifier(report)
        verifier.verify_all()
        count_results = [r for r in verifier.results
                         if r["check"] == "total_signals_matches_traces"]
        self.assertEqual(count_results[0]["status"], "FAIL")

    def test_detect_wrong_pass_rate(self):
        report = json.loads(json.dumps(self.report))
        report["aggregate_forensics"]["overall_pass_rate"] = 0.999
        verifier = ForensicsVerifier(report)
        verifier.verify_all()
        rate_results = [r for r in verifier.results
                        if r["check"] == "pass_rate_recompute"]
        self.assertEqual(rate_results[0]["status"], "FAIL")

    def test_detect_wrong_wilson_ci(self):
        report = json.loads(json.dumps(self.report))
        for gname in report["aggregate_forensics"]["per_gate_failure_rates"]:
            report["aggregate_forensics"]["per_gate_failure_rates"][gname]["wilson_ci"]["lower"] = 0.999
            break
        verifier = ForensicsVerifier(report)
        verifier.verify_all()
        ci_results = [r for r in verifier.results
                      if r["category"] == "wilson_ci" and r["status"] == "FAIL"]
        self.assertGreater(len(ci_results), 0)

    def test_total_checks_above_threshold(self):
        verifier = ForensicsVerifier(self.report)
        verifier.verify_all()
        total = sum(c["pass"] + c["fail"] for c in verifier.categories.values())
        self.assertGreaterEqual(total, 200,
                                f"Expected 200+ checks, got {total}")


# ── CLI Tests ────────────────────────────────────────────────────────────────

class TestCLI(unittest.TestCase):
    """Test command-line interface."""

    def test_load_signals_array(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump([make_signal()], f)
            f.flush()
            signals = load_signals(f.name)
            self.assertEqual(len(signals), 1)
        os.unlink(f.name)

    def test_load_signals_dict_with_signals_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"signals": [make_signal(), make_signal()]}, f)
            f.flush()
            signals = load_signals(f.name)
            self.assertEqual(len(signals), 2)
        os.unlink(f.name)

    def test_load_signals_invalid(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"data": "nope"}, f)
            f.flush()
            with self.assertRaises(ValueError):
                load_signals(f.name)
        os.unlink(f.name)

    def test_output_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as sf:
            json.dump([make_signal()], sf)
            sf.flush()
            outpath = sf.name + ".out.json"
            runner = ForensicsRunner()
            signals = load_signals(sf.name)
            report = runner.run(signals)
            with open(outpath, "w") as of:
                json.dump(report, of)
            with open(outpath) as of:
                loaded = json.load(of)
            self.assertEqual(loaded["schema_version"], "1.0.0")
            os.unlink(outpath)
        os.unlink(sf.name)


# ── Edge Cases ───────────────────────────────────────────────────────────────

class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""

    def test_zero_confidence(self):
        sig = make_signal(confidence=0.0)
        runner = ForensicsRunner()
        trace = runner.trace_signal(sig)
        self.assertIn("final_action", trace)

    def test_max_confidence(self):
        sig = make_signal(confidence=1.0)
        runner = ForensicsRunner()
        trace = runner.trace_signal(sig)
        self.assertIn("final_action", trace)

    def test_boundary_duration(self):
        # exactly at threshold
        sig = make_signal(regime="NEUTRAL", regime_duration_days=15)
        runner = ForensicsRunner()
        trace = runner.trace_signal(sig)
        self.assertEqual(trace["final_action"], "EMIT")

    def test_boundary_duration_minus_one(self):
        sig = make_signal(regime="NEUTRAL", regime_duration_days=14)
        runner = ForensicsRunner()
        trace = runner.trace_signal(sig)
        self.assertEqual(trace["final_action"], "WITHHOLD")

    def test_boundary_confidence(self):
        sig = make_signal(regime="NEUTRAL", regime_duration_days=20, confidence=0.30)
        runner = ForensicsRunner()
        trace = runner.trace_signal(sig)
        self.assertEqual(trace["final_action"], "EMIT")

    def test_missing_optional_fields(self):
        sig = {
            "signal_id": "test-001",
            "symbol": "BTC",
            "direction": "bullish",
            "confidence": 0.5,
            "outcome": 1.0,
            "direction_correct": True
        }
        runner = ForensicsRunner()
        trace = runner.trace_signal(sig)
        self.assertIn("stages", trace)

    def test_all_symbols(self):
        for sym in ["BTC", "ETH", "SOL", "LINK"]:
            sig = make_signal(symbol=sym, regime="NEUTRAL", regime_duration_days=20, confidence=0.5)
            runner = ForensicsRunner()
            trace = runner.trace_signal(sig)
            self.assertEqual(trace["symbol"], sym)

    def test_all_regimes(self):
        for regime in ["SYSTEMIC", "NEUTRAL", "DIVERGENCE", "EARNINGS", "UNKNOWN"]:
            sig = make_signal(regime=regime)
            runner = ForensicsRunner()
            trace = runner.trace_signal(sig)
            self.assertEqual(trace["regime"], regime)

    def test_single_signal_report(self):
        runner = ForensicsRunner()
        report = runner.run([make_signal()])
        self.assertEqual(report["report_meta"]["total_signals_traced"], 1)

    def test_large_batch(self):
        runner = ForensicsRunner()
        report = runner.run(make_batch(500))
        self.assertEqual(report["report_meta"]["total_signals_traced"], 500)


# ── Integration Tests ────────────────────────────────────────────────────────

class TestIntegration(unittest.TestCase):
    """Test end-to-end integration."""

    def test_report_passes_verifier(self):
        runner = ForensicsRunner()
        report = runner.run(make_batch(100))
        verifier = ForensicsVerifier(report)
        results = verifier.verify_all()
        failures = [r for r in results if r["status"] == "FAIL"]
        self.assertEqual(len(failures), 0,
                         "Verifier failures: " + str([(r["category"], r["check"], r["detail"]) for r in failures]))

    def test_mixed_regimes(self):
        signals = (
            [make_signal(signal_id=f"n-{i}", regime="NEUTRAL", regime_duration_days=20, confidence=0.5) for i in range(20)] +
            [make_signal(signal_id=f"s-{i}", regime="SYSTEMIC") for i in range(30)]
        )
        runner = ForensicsRunner()
        report = runner.run(signals)
        agg = report["aggregate_forensics"]
        # 30 SYSTEMIC should be withheld by regime gate
        regime_failures = agg["per_gate_failure_rates"]["regime_gate"]["failures"]
        self.assertEqual(regime_failures, 30)

    def test_sol_inversion(self):
        signals = [make_signal(signal_id=f"sol-{i}", symbol="SOL",
                               regime="NEUTRAL", regime_duration_days=20,
                               confidence=0.5)
                   for i in range(10)]
        runner = ForensicsRunner()
        report = runner.run(signals)
        # all SOL signals should be inverted
        for trace in report["signal_traces"]:
            self.assertEqual(trace["final_action"], "INVERT")
            self.assertEqual(trace["fate_changing_gate"], "weak_symbol_gate")

    def test_fate_change_consistency(self):
        runner = ForensicsRunner()
        report = runner.run(make_batch(200))
        for trace in report["signal_traces"]:
            if trace["has_fate_change"]:
                self.assertIsNotNone(trace["fate_changing_gate"])
                self.assertNotEqual(trace["final_action"], "EMIT")
            else:
                self.assertIsNone(trace["fate_changing_gate"])
                self.assertEqual(trace["final_action"], "EMIT")

    def test_all_gates_disabled(self):
        policy = {
            "description": "All disabled",
            "gates": {g: {"enabled": False} for g in
                      ["regime_gate", "duration_gate", "confidence_gate",
                       "voi_gate", "weak_symbol_gate"]},
            "symbols": {}
        }
        runner = ForensicsRunner(policy=policy)
        signals = [make_signal(regime="SYSTEMIC", confidence=0.01)]
        report = runner.run(signals)
        self.assertEqual(report["signal_traces"][0]["final_action"], "EMIT")
        self.assertFalse(report["signal_traces"][0]["has_fate_change"])

    def test_voi_gate_enabled(self):
        policy = json.loads(json.dumps(DEFAULT_POLICY))
        policy["gates"]["voi_gate"]["enabled"] = True
        policy["gates"]["voi_gate"]["min_voi"] = 0.0
        # BTC accuracy = 0.5586 → VOI = conf * (2*0.5586 - 1) = conf * 0.1172
        # for conf=0.5 → VOI = 0.0586 > 0 → pass
        runner = ForensicsRunner(policy=policy)
        sig = make_signal(symbol="BTC", regime="NEUTRAL", regime_duration_days=20, confidence=0.5)
        trace = runner.trace_signal(sig)
        voi_result = [g for g in trace["stages"]["routing"]["gate_results"]
                      if g["gate_name"] == "voi_gate"][0]
        self.assertEqual(voi_result["verdict"], "PASS")


# ── Real Data Tests ──────────────────────────────────────────────────────────

class TestRealData(unittest.TestCase):
    """Test with real resolved_signals.json if available."""

    @classmethod
    def setUpClass(cls):
        cls.real_data_path = "/home/postfiat/pf-consumer-backtest/resolved_signals.json"
        cls.has_real_data = os.path.exists(cls.real_data_path)
        if cls.has_real_data:
            with open(cls.real_data_path) as f:
                data = json.load(f)
            cls.signals = data["signals"][:200]  # sample for speed
        else:
            cls.signals = []

    @unittest.skipUnless(
        os.path.exists("/home/postfiat/pf-consumer-backtest/resolved_signals.json"),
        "Real data not available"
    )
    def test_real_data_traces(self):
        runner = ForensicsRunner()
        report = runner.run(self.signals)
        self.assertEqual(report["report_meta"]["total_signals_traced"], len(self.signals))

    @unittest.skipUnless(
        os.path.exists("/home/postfiat/pf-consumer-backtest/resolved_signals.json"),
        "Real data not available"
    )
    def test_real_data_passes_verifier(self):
        runner = ForensicsRunner()
        report = runner.run(self.signals)
        verifier = ForensicsVerifier(report)
        results = verifier.verify_all()
        failures = [r for r in results if r["status"] == "FAIL"]
        self.assertEqual(len(failures), 0,
                         f"Verifier failures on real data: {failures[:5]}")

    @unittest.skipUnless(
        os.path.exists("/home/postfiat/pf-consumer-backtest/resolved_signals.json"),
        "Real data not available"
    )
    def test_real_data_has_fate_changes(self):
        runner = ForensicsRunner()
        report = runner.run(self.signals)
        self.assertGreater(report["fate_changing_summary"]["total_fate_changes"], 0)

    @unittest.skipUnless(
        os.path.exists("/home/postfiat/pf-consumer-backtest/resolved_signals.json"),
        "Real data not available"
    )
    def test_real_data_regime_gate_failures(self):
        runner = ForensicsRunner()
        report = runner.run(self.signals)
        regime_rate = report["aggregate_forensics"]["per_gate_failure_rates"]["regime_gate"]
        # should have some SYSTEMIC signals that fail regime gate
        self.assertGreater(regime_rate["failures"], 0)

    @unittest.skipUnless(
        os.path.exists("/home/postfiat/pf-consumer-backtest/resolved_signals.json"),
        "Real data not available"
    )
    def test_real_data_sol_inversions(self):
        sol_signals = [s for s in self.signals if s["symbol"] == "SOL"]
        if sol_signals:
            runner = ForensicsRunner()
            report = runner.run(sol_signals)
            # SOL signals in NEUTRAL with sufficient duration should be inverted
            for trace in report["signal_traces"]:
                if (trace.get("regime") == "NEUTRAL" and
                    trace.get("regime_duration_days", 0) >= 15 and
                    trace.get("confidence", 0) >= 0.30):
                    self.assertEqual(trace["final_action"], "INVERT")

    @unittest.skipUnless(
        os.path.exists("/home/postfiat/pf-consumer-backtest/resolved_signals.json"),
        "Real data not available"
    )
    def test_real_data_chi_squared(self):
        runner = ForensicsRunner()
        report = runner.run(self.signals)
        chi2 = report["chi_squared_independence"]
        self.assertIn("contingency_table", chi2)
        self.assertGreater(chi2["degrees_of_freedom"], 0)

    @unittest.skipUnless(
        os.path.exists("/home/postfiat/pf-consumer-backtest/resolved_signals.json"),
        "Real data not available"
    )
    def test_real_data_content_hash_valid(self):
        runner = ForensicsRunner()
        report = runner.run(self.signals)
        # recompute hash
        hashable = {}
        for field in report["content_hash"]["fields_hashed"]:
            hashable[field] = report[field]
        raw = json.dumps(hashable, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        self.assertEqual(report["content_hash"]["content_hash"], expected)


# ── Additional Edge Cases ────────────────────────────────────────────────────

class TestAdditionalEdgeCases(unittest.TestCase):
    """Additional edge case coverage."""

    def test_duplicate_signal_ids(self):
        signals = [make_signal(signal_id="dup-001") for _ in range(5)]
        runner = ForensicsRunner()
        report = runner.run(signals)
        self.assertEqual(report["report_meta"]["total_signals_traced"], 5)

    def test_all_withhold(self):
        signals = [make_signal(signal_id=f"s-{i}", regime="SYSTEMIC") for i in range(10)]
        runner = ForensicsRunner()
        report = runner.run(signals)
        agg = report["aggregate_forensics"]
        self.assertAlmostEqual(agg["overall_pass_rate"], 0.0)
        self.assertEqual(agg["total_fate_changes"], 10)

    def test_all_emit(self):
        signals = [make_signal(signal_id=f"e-{i}", regime="NEUTRAL",
                               regime_duration_days=20, confidence=0.5)
                   for i in range(10)]
        runner = ForensicsRunner()
        report = runner.run(signals)
        self.assertAlmostEqual(report["aggregate_forensics"]["overall_pass_rate"], 1.0)

    def test_mixed_resolved_unresolved(self):
        resolved = [make_signal(signal_id=f"r-{i}", outcome=1.0) for i in range(5)]
        unresolved = []
        for i in range(5):
            s = make_signal(signal_id=f"u-{i}")
            del s["outcome"]
            del s["direction_correct"]
            unresolved.append(s)
        runner = ForensicsRunner()
        report = runner.run(resolved + unresolved)
        res_summary = report["aggregate_forensics"]["per_stage_summary"]["resolution"]
        self.assertEqual(res_summary["skip_count"], 5)

    def test_verifier_check_count_large_batch(self):
        runner = ForensicsRunner()
        report = runner.run(make_batch(200))
        verifier = ForensicsVerifier(report)
        verifier.verify_all()
        total = sum(c["pass"] + c["fail"] for c in verifier.categories.values())
        self.assertGreaterEqual(total, 400)

    def test_content_hash_changes_with_data(self):
        runner = ForensicsRunner()
        r1 = runner.run([make_signal(signal_id="a")])
        r2 = runner.run([make_signal(signal_id="b")])
        self.assertNotEqual(r1["content_hash"]["content_hash"],
                           r2["content_hash"]["content_hash"])

    def test_policy_with_voi_enabled(self):
        policy = json.loads(json.dumps(DEFAULT_POLICY))
        policy["gates"]["voi_gate"]["enabled"] = True
        policy["gates"]["voi_gate"]["min_voi"] = 0.5  # very high threshold
        runner = ForensicsRunner(policy=policy)
        sig = make_signal(symbol="BTC", regime="NEUTRAL",
                          regime_duration_days=20, confidence=0.3)
        trace = runner.trace_signal(sig)
        # low confidence + high VOI threshold = should fail VOI or confidence
        self.assertEqual(trace["final_action"], "WITHHOLD")

    def test_gate_failure_rates_have_wilson_ci(self):
        runner = ForensicsRunner()
        report = runner.run(make_batch(50))
        for gname, gdata in report["aggregate_forensics"]["per_gate_failure_rates"].items():
            self.assertIn("wilson_ci", gdata)
            ci = gdata["wilson_ci"]
            self.assertIn("lower", ci)
            self.assertIn("upper", ci)
            self.assertLessEqual(ci["lower"], ci["upper"])

    def test_fate_summary_gate_fractions_valid(self):
        runner = ForensicsRunner()
        report = runner.run(make_batch(100))
        fate = report["fate_changing_summary"]
        for g, v in fate["by_gate"].items():
            self.assertGreaterEqual(v["fraction"], 0)
            self.assertLessEqual(v["fraction"], 1.0)

    def test_failure_mode_fractions_valid(self):
        runner = ForensicsRunner()
        report = runner.run(make_batch(50))
        for mode in report["failure_mode_ranking"]:
            self.assertGreaterEqual(mode["fraction"], 0)
            self.assertLessEqual(mode["fraction"], 1.0)

    def test_chi_squared_cramers_v_range(self):
        runner = ForensicsRunner()
        report = runner.run(make_batch(100))
        v = report["chi_squared_independence"]["cramers_v"]
        self.assertGreaterEqual(v, 0)
        self.assertLessEqual(v, 1.0)

    def test_limitation_ids_unique(self):
        runner = ForensicsRunner()
        report = runner.run(make_batch(10))
        ids = [l["id"] for l in report["limitations"]]
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main()
