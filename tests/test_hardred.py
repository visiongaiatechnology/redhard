"""Unit, negative, security-boundary, and exporter tests for VGT HardRed Test."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from vgt_hardred.adapters.base import compute_context_maturity
from vgt_hardred.errors import SecurityBoundaryError, ValidationError
from vgt_hardred.exporters import export_attack_navigator_layer, export_ocsf_jsonl, export_sarif_json
from vgt_hardred.models import CaseResult, GroundTruthCase, PerfMetrics
from vgt_hardred.report_glass import generate_glass_html_report, generate_markdown_report
from vgt_hardred.scoring import score_contender
from vgt_hardred.vm_control import validate_remote_path, validate_snapshot_name


class TestSecurityBoundaries(unittest.TestCase):
    def test_rejects_path_traversal_and_unsafe_paths(self) -> None:
        for bad in ("/etc/passwd", "/tmp/hardred-sandbox/../etc/shadow", "/tmp/hardred-work;rm -rf /", "/var/log", ""):
            with self.assertRaises(SecurityBoundaryError):
                validate_remote_path(bad)

    def test_accepts_sandbox_paths(self) -> None:
        self.assertEqual(validate_remote_path("/tmp/hardred-sandbox/aes"), "/tmp/hardred-sandbox/aes")
        self.assertEqual(validate_remote_path("/dev/shm/hardred-sandbox/bin"), "/dev/shm/hardred-sandbox/bin")

    def test_rejects_bad_snapshot_names(self) -> None:
        for bad in ("snap;id", "../foo", "snap space", ""):
            with self.assertRaises(ValidationError):
                validate_snapshot_name(bad)


class TestScoringAndExporters(unittest.TestCase):
    def _sample_results(self, prot_fp_ep: bool = False) -> list[CaseResult]:
        c_atk = GroundTruthCase("EP-RANSOM-AES-01", "hardred-endpoint", "Ransom", "AES Burst", "attack", "T1486", "Impact", "hardred-probe", True)
        c_waf = GroundTruthCase("WAF-SQLI-01", "hardred-waf", "SQLi", "SQLi", "attack", "T1190", "Initial Access", "http", True)
        c_ben = GroundTruthCase("EP-BENIGN-01", "hardred-endpoint", "Benign", "Benign", "benign", "NONE", "None", "hardred-probe", False)
        return [
            CaseResult(c_atk, "2026-11-21T10:00:00Z", "2026-11-21T10:00:01Z", 900.0, True, True, 3, 120.0, 4, 120, evidence_summary="SIGKILL"),
            CaseResult(c_waf, "2026-11-21T10:00:02Z", "2026-11-21T10:00:02Z", 15.0, True, True, 2, 12.0, None, None, http_status=403, evidence_summary="403"),
            CaseResult(c_ben, "2026-11-21T10:00:03Z", "2026-11-21T10:00:03Z", 40.0, prot_fp_ep, prot_fp_ep, 0, None, None, None, evidence_summary="ok"),
        ]

    def test_gate_fails_on_endpoint_protection_fp(self) -> None:
        perf = PerfMetrics(http_rps=500, http_p95_ms=4.0, lynis_hardening_index=78, lsm_active=["bpf", "apparmor"])
        sc = score_contender("s1", "System 1", "snap-1", "2026-11-21T10:00:00Z", "2026-11-21T10:05:00Z", self._sample_results(prot_fp_ep=True), perf, perf)
        self.assertEqual(sc.gate_status, "FAIL")

    def test_gate_passes_clean_and_exports_valid_artifacts(self) -> None:
        perf = PerfMetrics(http_rps=500, http_p95_ms=4.0, lynis_hardening_index=78, lsm_active=["bpf", "apparmor"])
        sc = score_contender("gedefense", "GeDefense", "snap-1", "2026-11-21T10:00:00Z", "2026-11-21T10:05:00Z", self._sample_results(prot_fp_ep=False), perf, perf)
        self.assertEqual(sc.gate_status, "PASS")
        self.assertGreater(sc.overall_score, 40.0)

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            ocsf = export_ocsf_jsonl(sc, p / "out.ocsf.jsonl")
            sarif = export_sarif_json(sc, p / "out.sarif.json")
            att = export_attack_navigator_layer(sc, p / "out.attack.json")
            md = generate_markdown_report([sc], p / "report.md")
            html = generate_glass_html_report([sc], p / "dashboard.html")

            self.assertEqual(json.loads(ocsf.read_text().splitlines()[0])["class_uid"], 2004)
            self.assertEqual(json.loads(sarif.read_text())["version"], "2.1.0")
            self.assertEqual(json.loads(att.read_text())["versions"]["layer"], "4.5")
            self.assertIn("GeDefense", md.read_text())
            self.assertIn("VGT HardRed Test", html.read_text())
            self.assertNotIn("https://cdn.", html.read_text())

    def test_context_maturity_levels(self) -> None:
        self.assertEqual(compute_context_maturity([]), 0)
        self.assertEqual(compute_context_maturity([{"sensor": "x"}]), 1)
        self.assertEqual(compute_context_maturity([{"pid": 12, "rule_id": "R1"}]), 2)
        self.assertEqual(compute_context_maturity([{"pid": 12, "lineage": True}]), 3)

    def test_rescore_and_report_pipeline_generates_ranked_outputs(self) -> None:
        from vgt_hardred.cli import main

        base_perf = PerfMetrics(http_rps=800, http_p95_ms=2.0, lynis_hardening_index=62, lsm_active=["apparmor"])
        gd_perf = PerfMetrics(http_rps=720, http_p95_ms=2.5, lynis_hardening_index=74, lsm_active=["bpf", "apparmor"], security_rss_mib=180.0)
        base_sc = score_contender("baseline", "Baseline", "snap-0", "2026-11-21T10:00:00Z", "2026-11-21T10:02:00Z", self._sample_results(), base_perf, None)
        gd_sc = score_contender("gedefense", "GeDefense", "snap-1", "2026-11-21T10:05:00Z", "2026-11-21T10:08:00Z", self._sample_results(), gd_perf, base_perf)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, sc in (("baseline", base_sc), ("gedefense", gd_sc)):
                d = root / "results" / name
                d.mkdir(parents=True, exist_ok=True)
                (d / "scorecard.json").write_text(json.dumps(sc.to_dict()), encoding="utf-8")
            rc = main(["--root", str(root), "report"])
            self.assertEqual(rc, 0)
            self.assertTrue((root / "results" / "VGT_HardRed_Comparison.csv").is_file())
            self.assertTrue((root / "results" / "FINAL_BENCHMARK_REPORT.md").is_file())
            self.assertTrue((root / "results" / "VGT_HardRed_Dashboard.html").is_file())


if __name__ == "__main__":
    unittest.main()
