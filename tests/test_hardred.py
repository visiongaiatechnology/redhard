"""Unit, negative, security-boundary, and exporter tests for VGT HardRed Test."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from vgt_hardred.adapters.base import compute_context_maturity
from vgt_hardred.adapters.gedefense import _REMOTE_SNAPSHOT_PY, diff_snapshots
from vgt_hardred.adapters.safeline import diff_safeline_snapshots
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

    def test_prevention_tpr_excludes_detection_only_cases(self) -> None:
        perf = PerfMetrics(http_rps=500, http_p95_ms=4.0, lynis_hardening_index=78, lsm_active=["bpf"])
        c_prev = GroundTruthCase("EP-RANSOM-AES-01", "hardred-endpoint", "Ransom", "AES Burst", "attack", "T1486", "Impact", "hardred-probe", True)
        c_det_only = GroundTruthCase("EP-ART-T1087", "hardred-endpoint", "Discovery", "id", "attack", "T1087", "Discovery", "atomic", False)
        c_ben = GroundTruthCase("EP-BENIGN-01", "hardred-endpoint", "Benign", "Benign", "benign", "NONE", "None", "system-admin", False)
        results = [
            CaseResult(c_prev, "2026-11-21T10:00:00Z", "2026-11-21T10:00:01Z", 100.0, True, True, 3, 20.0, 2, 120),
            CaseResult(c_det_only, "2026-11-21T10:00:02Z", "2026-11-21T10:00:02Z", 10.0, True, False, 2, 10.0, None, None),
            CaseResult(c_ben, "2026-11-21T10:00:03Z", "2026-11-21T10:00:03Z", 10.0, False, False, 0, None, None, None),
        ]
        sc = score_contender("gedefense", "GeDefense", "snap-1", "2026-11-21T10:00:00Z", "2026-11-21T10:05:00Z", results, perf, perf)
        ep = sc.domain_scores["hardred-endpoint"]
        self.assertEqual(ep.prevention_tpr, 1.0)
        self.assertEqual(ep.detection_tpr, 1.0)

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


class TestGeDefenseTelemetryDiff(unittest.TestCase):
    def test_ignores_failed_429_before_sections_and_housekeeping_info(self) -> None:
        before = {
            "status": {
                "events": [
                    {"id": "ev-old", "kind": "malware.execution_blocked", "severity": "critical", "time": "2026-11-22T07:50:59Z"},
                ]
            },
            "titan_exec_events": {"_error": "HTTP 429 rate limited"},
            "worker_guard": {"_error": "HTTP 429 rate limited"},
            "styx": {"_error": "HTTP 429 rate limited"},
        }
        after = {
            "status": {
                "events": [
                    {"id": "ev-old", "kind": "malware.execution_blocked", "severity": "critical", "time": "2026-11-22T07:50:59Z"},
                    {"id": "ev-info", "kind": "titan_exec.policy_applied", "severity": "info", "time": "2026-11-22T07:51:00.1Z"},
                    {"id": "ev-bpf-tol", "kind": "xdr.bpf_guard_tolerated", "severity": "info", "time": "2026-11-22T07:51:00.2Z"},
                    {"id": "ev-sbc-info", "kind": "xdr.sbc_correlated", "severity": "info", "time": "2026-11-22T07:51:00.3Z"},
                ]
            },
            "titan_exec_events": {"events": [{"ts_ns": 1, "pid": 4076, "comm": "hardred-probe", "rule_id": "TITAN.EXEC_DENIED", "action": 2}]},
            "worker_guard": {"counters": {"events": 3}},
            "styx": {"kernel_health": {"PolicyDrops": 3}},
        }
        verdict = diff_snapshots(before, after, "2026-11-22T07:51:00Z")
        self.assertFalse(verdict.detected)
        self.assertEqual(verdict.raw_alerts, [])

    def test_detects_real_malware_and_exec_denials(self) -> None:
        before = {
            "status": {"events": []},
            "titan_exec_events": {"events": []},
        }
        after = {
            "status": {"events": [{"id": "ev-new", "kind": "malware.execution_blocked", "severity": "critical", "time": "2026-11-22T07:51:01Z"}]},
            "titan_exec_events": {"events": [{"ts_ns": 2, "pid": 5123, "comm": "payload", "rule_id": "TITAN.EXEC_DENIED", "action": 2}]},
        }
        verdict = diff_snapshots(before, after, "2026-11-22T07:51:00Z")
        self.assertTrue(verdict.detected)
        self.assertEqual(verdict.context_maturity, 3)

    def test_remote_snapshot_script_executes_without_scoping_errors(self) -> None:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import os
        import subprocess
        import sys
        import threading

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                body = b"[]" if ("attack-stories" in self.path or "responses" in self.path) else b'{"ok": true}'
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                return

        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            script = _REMOTE_SNAPSHOT_PY.replace(
                'subprocess.check_output(\n    ["sudo", "cat", "/var/lib/vgt/gedefense-access/dashboard.token"], text=True\n).strip()',
                '"test-token"',
            )
            env = {**os.environ, "GD_API_PORT": str(srv.server_port)}
            proc = subprocess.run([sys.executable, "-"], input=script, capture_output=True, text=True, env=env, timeout=10, check=True)
            parsed = json.loads(proc.stdout.strip().splitlines()[-1])
            self.assertEqual(parsed["status"], {"ok": True})
            self.assertEqual(parsed["attack_stories"], [])
        finally:
            srv.shutdown()
            srv.server_close()


class TestSafeLineTelemetryDiff(unittest.TestCase):
    def test_ignores_baseline_events_and_matches_new_safeline_and_acl_events(self) -> None:
        before = {
            "records": [{"event_id": "old-1", "src_ip": "192.168.56.1", "rule_id": "m_sqli", "timestamp": 1795472400}],
            "acl_records": [{"id": 1, "ip": "192.168.56.1", "action": "block"}],
        }
        after_same = {
            "records": [{"event_id": "old-1", "src_ip": "192.168.56.1", "rule_id": "m_sqli", "timestamp": 1795472400}],
            "acl_records": [{"id": 1, "ip": "192.168.56.1", "action": "block"}],
        }
        verdict_clean = diff_safeline_snapshots(before, after_same, "2026-11-23T22:21:00Z")
        self.assertFalse(verdict_clean.detected)
        self.assertEqual(verdict_clean.raw_alerts, [])

        after_new = {
            "records": [
                *after_same["records"],
                {
                    "event_id": "new-2",
                    "src_ip": "192.168.56.1",
                    "url_path": "/index.php?q=<script>alert(1)</script>",
                    "rule_id": "m_xss",
                    "module": "m_xss",
                    "dst_port": 80,
                    "action": 1,
                    "risk_level": 3,
                    "timestamp": 1795472470,
                },
            ],
            "acl_records": [
                *after_same["acl_records"],
                {"id": 2, "ip": "192.168.56.1", "action": "block", "result": "block", "period": 10, "count": 100, "created_at": "2026-11-23T22:21:11Z"},
            ],
        }
        verdict_hit = diff_safeline_snapshots(before, after_new, "2026-11-23T22:21:10Z")
        self.assertTrue(verdict_hit.detected)
        self.assertEqual(verdict_hit.context_maturity, 2)
        self.assertEqual(len(verdict_hit.raw_alerts), 2)
        self.assertIn("m_xss", verdict_hit.evidence_summary)
        self.assertIn("safeline/acl/block", verdict_hit.evidence_summary)


class TestClockCalibrationAndStageResume(unittest.TestCase):
    def test_measure_clock_offset_selects_min_rtt_not_max(self) -> None:
        from unittest.mock import patch
        from vgt_hardred.vm_control import VMConfig, VMController

        cfg = VMConfig.from_dict({
            "name": "test-vm",
            "vboxmanage": "VBoxManage",
            "ssh_exe": "ssh",
            "scp_exe": "scp",
            "ssh_key": "k",
            "control_host": "127.0.0.1",
            "control_port": 2222,
            "control_user": "pentest",
            "target_ip": "192.168.56.50",
            "http_base_url": "http://192.168.56.50",
            "https_base_url": "https://192.168.56.50",
            "remote_work_dir": "/tmp/hardred-work",
            "sandbox_root": "/tmp/hardred-sandbox",
            "shm_sandbox_root": "/dev/shm/hardred-sandbox",
        })
        vm = VMController(cfg)

        ssh_outputs = [(0, "999.900000\n", ""), (0, "999.355000\n", ""), (0, "1000.110000\n", "")]
        perf_seq = iter([
            10.0, 10.200,
            20.0, 20.010,
            30.0, 30.080,
            31.0,
        ])
        with patch.object(vm, "ssh", side_effect=ssh_outputs), \
             patch("vgt_hardred.vm_control.time.time", side_effect=[999.300, 1000.000, 1000.000]), \
             patch("vgt_hardred.vm_control.time.monotonic", return_value=50.0), \
             patch("vgt_hardred.vm_control.time.perf_counter", side_effect=perf_seq):
            offset = vm.measure_clock_offset(samples=3, force_refresh=True)
        self.assertAlmostEqual(offset, -0.650, places=3)

    def test_gedefense_clock_offset_removes_positive_bias(self) -> None:
        before = {"status": {"events": []}}
        after = {
            "status": {
                "events": [
                    {
                        "id": "ev-fast",
                        "kind": "l7.blocked",
                        "severity": "high",
                        "time": "2026-11-23T22:20:00.018000Z",
                    }
                ]
            }
        }
        verdict = diff_snapshots(before, after, "2026-11-23T22:20:00.650000Z", vm_clock_offset=-0.650)
        self.assertTrue(verdict.detected)
        self.assertIsNotNone(verdict.ttfa_ms)
        self.assertAlmostEqual(verdict.ttfa_ms or 0.0, 18.0, delta=0.5)

    def test_stage_checkpoint_deserialization_roundtrip(self) -> None:
        from vgt_hardred.cli import _deserialize_case_results
        from vgt_hardred.models import CaseResult, GroundTruthCase

        sample = [
            CaseResult(
                GroundTruthCase("EP-RANSOM-AES-01", "hardred-endpoint", "Ransom", "AES", "attack", "T1486", "Impact", "hardred-probe", True),
                "2026-11-21T10:00:00Z", "2026-11-21T10:00:01Z", 900.0, True, True, 3, 120.0, 4, 120, evidence_summary="SIGKILL",
            )
        ]
        restored = _deserialize_case_results([c.to_dict() for c in sample])
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0].case.case_id, "EP-RANSOM-AES-01")
        self.assertTrue(restored[0].prevented)


if __name__ == "__main__":
    unittest.main()
