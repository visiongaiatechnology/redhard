"""Command-line orchestrator for VGT HardRed Test."""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vgt_hardred.adapters.baseline import BaselineAdapter
from vgt_hardred.adapters.crowdsec import CrowdSecAdapter
from vgt_hardred.adapters.gedefense import GeDefenseAdapter
from vgt_hardred.adapters.wazuh import WazuhAdapter
from vgt_hardred.errors import ValidationError
from vgt_hardred.exporters import (
    export_attack_navigator_layer,
    export_ocsf_jsonl,
    export_sarif_json,
    export_summary_csv,
)
from vgt_hardred.models import CaseResult, ContenderScorecard, PerfMetrics
from vgt_hardred.report_glass import generate_glass_html_report, generate_markdown_report
from vgt_hardred.runners.compliance_runner import run_compliance_domain
from vgt_hardred.runners.endpoint_runner import run_endpoint_domain
from vgt_hardred.runners.malware_runner import run_malware_domain
from vgt_hardred.runners.netids_runner import run_netids_attacks, run_netids_benign
from vgt_hardred.runners.perf_runner import run_perf_domain
from vgt_hardred.runners.waf_runner import run_gotestwaf_corpus, run_waf_attacks, run_waf_benign
from vgt_hardred.scoring import score_contender
from vgt_hardred.vm_control import VMConfig, VMController


def _make_adapter(cid: str, vm: VMController):
    if cid == "baseline":
        return BaselineAdapter(vm)
    if cid == "gedefense":
        return GeDefenseAdapter(vm)
    if cid == "crowdsec":
        return CrowdSecAdapter(vm)
    if cid == "wazuh":
        return WazuhAdapter(vm)
    raise ValidationError(f"Unknown contender adapter: {cid!r}")


def run_contender_suite(
    root: Path,
    targets_cfg: dict[str, Any],
    contender_id: str,
    baseline_perf: PerfMetrics | None = None,
    skip_restore: bool = False,
) -> ContenderScorecard:
    vm_cfg = VMConfig.from_dict(targets_cfg["vm"])
    c_cfg = targets_cfg["contenders"][contender_id]
    vm = VMController(vm_cfg)
    adapter = _make_adapter(contender_id, vm)

    results_dir = root / "results" / contender_id
    results_dir.mkdir(parents=True, exist_ok=True)

    snapshot = str(c_cfg["snapshot"])
    if not skip_restore:
        vm.restore_and_boot_snapshot(snapshot, settle_sec=14)
    adapter.prepare()

    netbench_bin = root / "probes" / "bin" / "hardred-netbench.exe"
    probe_linux_bin = root / "probes" / "bin" / "hardred-probe-linux-amd64"
    evgen_linux_bin = root / "third_party" / "bin" / "event-generator-linux-amd64"
    gotestwaf_bin = root / "third_party" / "bin" / "gotestwaf.exe"
    lynis_dir = root / "third_party" / "lynis"
    atomic_dir = root / "third_party" / "atomic-red-team" / "atomics"

    started_utc = datetime.now(timezone.utc).isoformat()
    all_cases: list[CaseResult] = []
    extra_meta: dict[str, Any] = {}

    # Strict zero-contamination execution order:
    # 1) All Benign Network Controls FIRST on fresh boot (HTTP Keep-Alive = 6 total TCP connections)
    all_cases.extend(run_waf_benign(vm, adapter))
    all_cases.extend(run_netids_benign(vm, adapter))

    # 2) Malware + Endpoint + Compliance over isolated NAT control plane (~75s lets eth1 rate windows reset to 0)
    clamav_dir = root / "third_party" / "clamav-testfiles"
    mal_cases, mal_meta = run_malware_domain(vm, adapter, clamav_dir=clamav_dir)
    all_cases.extend(mal_cases)
    extra_meta["malware"] = mal_meta

    ep_cases, ep_meta = run_endpoint_domain(vm, adapter, probe_linux_bin, evgen_linux_bin, atomic_dir)
    all_cases.extend(ep_cases)
    extra_meta["endpoint"] = ep_meta

    hardening_idx, lsm_active, comp_meta = run_compliance_domain(vm, lynis_dir)
    extra_meta["compliance"] = comp_meta

    # 3) Targeted WAF attacks (14 requests, < 20/min window)
    adapter.clear_attacker_blocks()
    waf_cases = run_waf_attacks(vm, adapter)
    all_cases.extend(waf_cases)

    # 4) Perf benchmark on clean unbanned IP (after clearing any WAF IP block)
    adapter.clear_attacker_blocks()
    time.sleep(0.5)
    perf = run_perf_domain(vm, adapter, netbench_bin, hardening_idx, lsm_active)
    adapter.clear_attacker_blocks()

    # 5) NetIDS flood/bruteforce/portscan + GoTestWAF 675-request corpus LAST
    net_cases, net_meta = run_netids_attacks(vm, adapter, netbench_bin)
    all_cases.extend(net_cases)
    extra_meta["netids"] = net_meta

    adapter.clear_attacker_blocks()
    extra_meta["waf"] = run_gotestwaf_corpus(vm, results_dir, gotestwaf_bin, adapter=adapter)

    ended_utc = datetime.now(timezone.utc).isoformat()
    scorecard = score_contender(
        contender_id=contender_id,
        contender_label=str(c_cfg["label"]),
        snapshot=snapshot,
        run_started_utc=started_utc,
        run_ended_utc=ended_utc,
        case_results=all_cases,
        perf=perf,
        baseline_perf=baseline_perf,
    )

    (results_dir / "scorecard.json").write_text(
        json.dumps(scorecard.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (results_dir / "meta.json").write_text(
        json.dumps(extra_meta, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    export_ocsf_jsonl(scorecard, results_dir / f"{contender_id}.ocsf.jsonl")
    export_sarif_json(scorecard, results_dir / f"{contender_id}.sarif.json")
    export_attack_navigator_layer(scorecard, results_dir / f"{contender_id}.attack_layer.json")
    return scorecard


def rescore_and_report(root: Path) -> tuple[Path, Path, Path]:
    results_root = root / "results"
    raw_cards: list[dict[str, Any]] = []
    for sub in ("baseline", "gedefense", "crowdsec", "wazuh"):
        p = results_root / sub / "scorecard.json"
        if p.is_file():
            raw_cards.append(json.loads(p.read_text(encoding="utf-8")))

    baseline_perf: PerfMetrics | None = None
    for rc in raw_cards:
        if rc["contender_id"] == "baseline":
            baseline_perf = PerfMetrics(**rc["perf"])
            break

    from vgt_hardred.models import GroundTruthCase

    scorecards: list[ContenderScorecard] = []
    for rc in raw_cards:
        cases: list[CaseResult] = []
        for item in rc["case_results"]:
            c_obj = GroundTruthCase(**item["case"])
            cases.append(
                CaseResult(
                    case=c_obj,
                    started_utc=item["started_utc"],
                    ended_utc=item["ended_utc"],
                    duration_ms=item["duration_ms"],
                    detected=item["detected"],
                    prevented=item["prevented"],
                    context_maturity=item["context_maturity"],
                    ttfa_ms=item["ttfa_ms"],
                    pre_kill_damage=item["pre_kill_damage"],
                    pre_kill_total=item["pre_kill_total"],
                    http_status=item.get("http_status"),
                    exit_code=item.get("exit_code"),
                    evidence_summary=item.get("evidence_summary", ""),
                    raw_alerts=item.get("raw_alerts", []),
                    error=item.get("error", ""),
                )
            )
        perf = PerfMetrics(**rc["perf"])
        sc = score_contender(
            contender_id=rc["contender_id"],
            contender_label=rc["contender_label"],
            snapshot=rc["snapshot"],
            run_started_utc=rc["run_started_utc"],
            run_ended_utc=rc["run_ended_utc"],
            case_results=cases,
            perf=perf,
            baseline_perf=baseline_perf,
        )
        (results_root / sc.contender_id / "scorecard.json").write_text(
            json.dumps(sc.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
        )
        scorecards.append(sc)

    csv_path = export_summary_csv(scorecards, results_root / "VGT_HardRed_Comparison.csv")
    md_path = generate_markdown_report(scorecards, results_root / "FINAL_BENCHMARK_REPORT.md")
    html_path = generate_glass_html_report(scorecards, results_root / "VGT_HardRed_Dashboard.html")
    return csv_path, md_path, html_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vgt-hardred", description="VGT HardRed Test Orchestrator")
    parser.add_argument("--root", default=".", help="Repository root path")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="Run live benchmark against one or all contenders")
    p_run.add_argument("--contenders", default="baseline,gedefense,crowdsec,wazuh")
    p_run.add_argument("--skip-restore", action="store_true")

    sub.add_parser("report", help="Re-score saved scorecards and generate comparison report + Glass HTML")

    args = parser.parse_args(argv)
    root = Path(args.root).resolve()

    if args.cmd == "report":
        csv_p, md_p, html_p = rescore_and_report(root)
        print(json.dumps({"csv": str(csv_p), "md": str(md_p), "html": str(html_p)}))
        return 0

    targets = json.loads((root / "configs" / "targets.json").read_text(encoding="utf-8"))
    selected = [c.strip() for c in args.contenders.split(",") if c.strip()]

    baseline_perf: PerfMetrics | None = None
    existing_base = root / "results" / "baseline" / "scorecard.json"
    if existing_base.is_file():
        baseline_perf = PerfMetrics(**json.loads(existing_base.read_text(encoding="utf-8"))["perf"])

    for cid in selected:
        if cid not in targets["contenders"]:
            raise ValidationError(f"Unknown contender: {cid}")
        sc = run_contender_suite(root, targets, cid, baseline_perf=baseline_perf, skip_restore=args.skip_restore)
        if cid == "baseline":
            baseline_perf = sc.perf
        print(json.dumps({"contender": cid, "overall": sc.overall_score, "gate": sc.gate_status}))

    csv_p, md_p, html_p = rescore_and_report(root)
    print(json.dumps({"csv": str(csv_p), "md": str(md_p), "html": str(html_p)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
