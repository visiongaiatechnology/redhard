"""Exporters for OCSF v1.9.0 JSONL, SARIF v2.1.0, MITRE ATT&CK Navigator v4.5, and CSV."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from vgt_hardred.models import CaseResult, ContenderScorecard

_SEV_MAP = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def export_ocsf_jsonl(scorecard: ContenderScorecard, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for res in scorecard.case_results:
        if not (res.detected or res.prevented):
            continue
        event = {
            "class_uid": 2004,
            "class_name": "Detection Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "activity_id": 1,
            "severity_id": _SEV_MAP.get(res.case.severity, 3),
            "time": res.started_utc,
            "metadata": {
                "version": "1.9.0",
                "product": {
                    "name": scorecard.contender_label,
                    "uid": scorecard.contender_id,
                },
            },
            "finding_info": {
                "uid": f"{scorecard.contender_id}:{res.case.case_id}",
                "title": res.case.title,
                "desc": res.evidence_summary or res.case.category,
                "types": [res.case.domain, res.case.category],
                "attacks": [
                    {
                        "technique": {"uid": res.case.mitre_technique, "name": res.case.category},
                        "tactic": {"name": res.case.mitre_tactic},
                    }
                ],
            },
            "action_id": 2 if res.prevented else 1,
            "action": "Denied" if res.prevented else "Allowed",
            "status_id": 1 if res.case.polarity == "attack" else 3,
            "unmapped": {
                "polarity": res.case.polarity,
                "context_maturity": res.context_maturity,
                "ttfa_ms": res.ttfa_ms,
                "pre_kill_damage": res.pre_kill_damage,
                "pre_kill_total": res.pre_kill_total,
            },
        }
        lines.append(json.dumps(event, ensure_ascii=False))
    out_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return out_path


def export_sarif_json(scorecard: ContenderScorecard, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for res in scorecard.case_results:
        rules.setdefault(
            res.case.case_id,
            {
                "id": res.case.case_id,
                "name": res.case.category,
                "shortDescription": {"text": res.case.title},
                "properties": {
                    "domain": res.case.domain,
                    "mitre_technique": res.case.mitre_technique,
                    "polarity": res.case.polarity,
                },
            },
        )
        if res.case.polarity == "attack" and (res.detected and res.prevented):
            level = "note"
            msg = f"[BLOCKED+DETECTED] {res.case.title} ({res.evidence_summary})"
        elif res.case.polarity == "attack" and (res.detected or res.prevented):
            level = "warning"
            msg = f"[PARTIAL det={res.detected} prev={res.prevented}] {res.case.title} ({res.evidence_summary})"
        elif res.case.polarity == "attack":
            level = "error"
            msg = f"[MISSED] {res.case.title} (expected defense failed)"
        elif res.detected or res.prevented:
            level = "error"
            msg = f"[FALSE_POSITIVE det={res.detected} prev={res.prevented}] {res.case.title}"
        else:
            level = "none"
            msg = f"[BENIGN_PASS] {res.case.title}"

        results.append(
            {
                "ruleId": res.case.case_id,
                "level": level,
                "message": {"text": msg},
                "properties": {
                    "detected": res.detected,
                    "prevented": res.prevented,
                    "context_maturity": res.context_maturity,
                    "ttfa_ms": res.ttfa_ms,
                    "pre_kill_damage": res.pre_kill_damage,
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": f"VGT-HardRed::{scorecard.contender_id}",
                        "semanticVersion": "1.0.1",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    out_path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path


def export_attack_navigator_layer(scorecard: ContenderScorecard, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    by_tech: dict[str, list[CaseResult]] = {}
    for res in scorecard.case_results:
        if res.case.polarity == "attack" and res.case.mitre_technique:
            by_tech.setdefault(res.case.mitre_technique, []).append(res)

    techniques = []
    for tech_id, items in sorted(by_tech.items()):
        det = sum(1 for r in items if r.detected)
        prev = sum(1 for r in items if r.prevented)
        tot = len(items)
        if prev == tot:
            color = "#176e68"
            score = 100
        elif det == tot or prev > 0:
            color = "#c98515"
            score = 60
        elif det > 0:
            color = "#d99b26"
            score = 40
        else:
            color = "#b43b36"
            score = 0
        techniques.append(
            {
                "techniqueID": tech_id,
                "score": score,
                "color": color,
                "comment": f"detected={det}/{tot}, prevented={prev}/{tot}",
                "enabled": True,
            }
        )

    layer = {
        "name": f"VGT HardRed — {scorecard.contender_label}",
        "versions": {"attack": "16", "navigator": "4.5", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Generated by VGT HardRed Test for {scorecard.contender_id} ({scorecard.overall_score}/100)",
        "techniques": techniques,
    }
    out_path.write_text(json.dumps(layer, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path


def export_summary_csv(scorecards: list[ContenderScorecard], out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "rank",
                "contender_id",
                "contender_label",
                "overall_score",
                "axis1_efficacy",
                "axis2_fp_resilience",
                "axis3_latency_containment",
                "axis4_overhead",
                "gate_status",
                "waf_det_tpr",
                "waf_prev_tpr",
                "netids_det_tpr",
                "netids_prev_tpr",
                "endpoint_det_tpr",
                "endpoint_prev_tpr",
                "malware_det_tpr",
                "malware_prev_tpr",
                "lynis_index",
                "http_p95_ms",
                "security_rss_mib",
            ]
        )
        ranked = sorted(scorecards, key=lambda s: s.overall_score, reverse=True)
        for idx, sc in enumerate(ranked, start=1):
            writer.writerow(
                [
                    idx,
                    sc.contender_id,
                    sc.contender_label,
                    sc.overall_score,
                    sc.axis1_efficacy,
                    sc.axis2_fp_resilience,
                    sc.axis3_latency_containment,
                    sc.axis4_overhead,
                    sc.gate_status,
                    sc.domain_scores["hardred-waf"].detection_tpr,
                    sc.domain_scores["hardred-waf"].prevention_tpr,
                    sc.domain_scores["hardred-netids"].detection_tpr,
                    sc.domain_scores["hardred-netids"].prevention_tpr,
                    sc.domain_scores["hardred-endpoint"].detection_tpr,
                    sc.domain_scores["hardred-endpoint"].prevention_tpr,
                    sc.domain_scores["hardred-malware"].detection_tpr,
                    sc.domain_scores["hardred-malware"].prevention_tpr,
                    sc.compliance_index,
                    sc.perf.http_p95_ms,
                    sc.perf.security_rss_mib,
                ]
            )
    return out_path
