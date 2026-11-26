"""4-Axis scoring engine implementing separated Detection/Prevention TPR & FPR and Gate checks."""

from __future__ import annotations

import math
import statistics
from collections import defaultdict

from vgt_hardred.models import CaseResult, ContenderScorecard, DomainScore, PerfMetrics

DOMAIN_WEIGHTS: dict[str, float] = {
    "hardred-waf": 0.25,
    "hardred-netids": 0.20,
    "hardred-endpoint": 0.35,
    "hardred-malware": 0.10,
    "hardred-compliance": 0.10,
}


def _ttfa_to_score(median_ttfa_ms: float | None, detection_tpr: float) -> float:
    if detection_tpr <= 0.0 or median_ttfa_ms is None:
        return 0.0
    ms = max(1.0, float(median_ttfa_ms))
    # Log scale: <= 50ms -> 100, 500ms -> ~84, 5000ms -> ~58, 30000ms -> ~30
    if ms <= 50.0:
        return 100.0
    score = 100.0 - 24.0 * math.log10(ms / 50.0)
    return round(max(0.0, min(100.0, score)), 2)


def compute_domain_score(
    domain: str,
    results: list[CaseResult],
    perf: PerfMetrics,
) -> DomainScore:
    if domain == "hardred-compliance":
        comp_score = round(min(100.0, float(perf.lynis_hardening_index) + min(15.0, len(perf.lsm_active) * 2.0)), 2)
        return DomainScore(
            domain=domain,
            attack_total=0,
            benign_total=0,
            detected_tp=0,
            prevented_tp=0,
            detection_fp=0,
            protection_fp=0,
            detection_tpr=1.0 if comp_score >= 70 else round(comp_score / 100.0, 4),
            prevention_tpr=round(comp_score / 100.0, 4),
            detection_fpr=0.0,
            protection_fpr=0.0,
            balanced_accuracy=round(comp_score / 100.0, 4),
            youden_j=round(comp_score / 100.0, 4),
            avg_context_maturity=3.0 if comp_score >= 80 else 2.0,
            median_ttfa_ms=None,
            avg_damage_ratio=None,
            domain_score=comp_score,
        )

    attacks = [r for r in results if r.case.polarity == "attack"]
    benign = [r for r in results if r.case.polarity == "benign"]
    prev_attacks = [r for r in attacks if r.case.expected_prevention]

    a_tot = len(attacks)
    b_tot = len(benign)
    det_tp = sum(1 for r in attacks if r.detected)
    prev_tot = len(prev_attacks) if prev_attacks else a_tot
    prev_tp = sum(1 for r in prev_attacks if r.prevented) if prev_attacks else sum(1 for r in attacks if r.prevented)
    det_fp = sum(1 for r in benign if r.detected)
    prot_fp = sum(1 for r in benign if r.prevented)

    det_tpr = (det_tp / a_tot) if a_tot else 0.0
    prev_tpr = (prev_tp / prev_tot) if prev_tot else 0.0
    det_fpr = (det_fp / b_tot) if b_tot else 0.0
    prot_fpr = (prot_fp / b_tot) if b_tot else 0.0

    # Balanced Accuracy uses best combined true-response rate vs combined FP impact.
    combined_tpr = sum(1 for r in attacks if (r.detected or r.prevented)) / a_tot if a_tot else 0.0
    tnr = 1.0 - max(det_fpr, prot_fpr)
    bal_acc = (combined_tpr + tnr) / 2.0
    youden = combined_tpr - max(det_fpr, prot_fpr)

    ctx_vals = [r.context_maturity for r in attacks if (r.detected or r.prevented)]
    avg_ctx = (sum(ctx_vals) / len(ctx_vals)) if ctx_vals else 0.0

    ttfas = [r.ttfa_ms for r in attacks if r.ttfa_ms is not None and (r.detected or r.prevented)]
    med_ttfa = round(statistics.median(ttfas), 2) if ttfas else None

    dmg_ratios = [
        (r.pre_kill_damage / r.pre_kill_total)
        for r in attacks
        if r.pre_kill_damage is not None and r.pre_kill_total and r.pre_kill_total > 0
    ]
    avg_dmg = round(sum(dmg_ratios) / len(dmg_ratios), 4) if dmg_ratios else None

    # Domain Score on [0, 100]: Detection TPR 30%, Prevention TPR 45%, Balanced Acc 15%, Context 10%
    domain_score = 100.0 * (
        0.30 * det_tpr
        + 0.45 * prev_tpr
        + 0.15 * max(0.0, bal_acc)
        + 0.10 * (avg_ctx / 3.0)
    )
    return DomainScore(
        domain=domain,
        attack_total=a_tot,
        benign_total=b_tot,
        detected_tp=det_tp,
        prevented_tp=prev_tp,
        detection_fp=det_fp,
        protection_fp=prot_fp,
        detection_tpr=round(det_tpr, 4),
        prevention_tpr=round(prev_tpr, 4),
        detection_fpr=round(det_fpr, 4),
        protection_fpr=round(prot_fpr, 4),
        balanced_accuracy=round(bal_acc, 4),
        youden_j=round(youden, 4),
        avg_context_maturity=round(avg_ctx, 2),
        median_ttfa_ms=med_ttfa,
        avg_damage_ratio=avg_dmg,
        domain_score=round(domain_score, 2),
    )


def score_contender(
    contender_id: str,
    contender_label: str,
    snapshot: str,
    run_started_utc: str,
    run_ended_utc: str,
    case_results: list[CaseResult],
    perf: PerfMetrics,
    baseline_perf: PerfMetrics | None = None,
) -> ContenderScorecard:
    by_domain: dict[str, list[CaseResult]] = defaultdict(list)
    for res in case_results:
        by_domain[res.case.domain].append(res)

    domain_scores: dict[str, DomainScore] = {}
    for dom in DOMAIN_WEIGHTS:
        domain_scores[dom] = compute_domain_score(dom, by_domain.get(dom, []), perf)

    # Axis 1: Weighted Efficacy across all 5 security domains (0-100)
    axis1 = round(
        sum(domain_scores[dom].domain_score * w for dom, w in DOMAIN_WEIGHTS.items()),
        2,
    )

    # Axis 2: False-Positive Resilience (0-100) & Strict AMTSO/WCP Gates
    all_benign = [r for r in case_results if r.case.polarity == "benign"]
    b_total = len(all_benign)
    det_fp_total = sum(1 for r in all_benign if r.detected)
    prot_fp_total = sum(1 for r in all_benign if r.prevented)
    det_fpr_all = (det_fp_total / b_total) if b_total else 0.0
    prot_fpr_all = (prot_fp_total / b_total) if b_total else 0.0

    ep_score = domain_scores["hardred-endpoint"]
    waf_score = domain_scores["hardred-waf"]
    gate_reasons: list[str] = []
    gate_status: str = "PASS"

    if contender_id != "baseline":
        if ep_score.protection_fpr > 0.0:
            gate_status = "FAIL"
            gate_reasons.append(f"Endpoint Protection FPR {ep_score.protection_fpr*100:.2f}% > 0% gate")
        if waf_score.protection_fpr > 0.01:
            gate_status = "FAIL"
            gate_reasons.append(f"WAF Protection FPR {waf_score.protection_fpr*100:.2f}% > 1% gate")
        if ep_score.detection_fpr > 0.05 or waf_score.detection_fpr > 0.05:
            if gate_status == "PASS":
                gate_status = "CONDITIONAL"
            gate_reasons.append(
                f"Detection FPR elevated (EP={ep_score.detection_fpr*100:.1f}%, WAF={waf_score.detection_fpr*100:.1f}%)"
            )
    else:
        gate_status = "CONDITIONAL"
        gate_reasons.append("Unprotected baseline control target")

    if contender_id == "baseline":
        axis2 = 100.0 if prot_fp_total == 0 else 0.0
    else:
        axis2 = round(max(0.0, 100.0 - (det_fpr_all * 200.0 + prot_fpr_all * 600.0)), 2)

    # Axis 3: Latency & Damage Containment (0-100)
    ttfa_list = [r.ttfa_ms for r in case_results if r.case.polarity == "attack" and r.ttfa_ms is not None and (r.detected or r.prevented)]
    atk_total = sum(1 for r in case_results if r.case.polarity == "attack")
    atk_det_or_prev = sum(1 for r in case_results if r.case.polarity == "attack" and (r.detected or r.prevented))
    det_cov = (atk_det_or_prev / atk_total) if atk_total else 0.0
    med_ttfa_global = statistics.median(ttfa_list) if ttfa_list else None
    ttfa_score = _ttfa_to_score(med_ttfa_global, det_cov) * (0.4 + 0.6 * det_cov)

    dmg_vals = [
        (r.pre_kill_damage / r.pre_kill_total)
        for r in case_results
        if r.pre_kill_damage is not None and r.pre_kill_total and r.pre_kill_total > 0
    ]
    containment_score = (1.0 - (sum(dmg_vals) / len(dmg_vals))) * 100.0 if dmg_vals else (det_cov * 100.0)
    axis3 = round(0.55 * ttfa_score + 0.45 * containment_score, 2)

    # Axis 4: Overhead & Operational Stability vs Baseline (0-100)
    if baseline_perf is None or contender_id == "baseline":
        axis4 = 100.0
    else:
        p95_base = max(0.5, baseline_perf.http_p95_ms)
        p95_delta_ratio = max(0.0, (perf.http_p95_ms - p95_base) / p95_base)
        http_penalty = min(35.0, p95_delta_ratio * 25.0)

        rss_penalty = min(30.0, (perf.security_rss_mib / 1024.0) * 18.0)
        cpu_penalty = min(20.0, (perf.security_cpu_pct / 100.0) * 35.0)

        io_penalty = 0.0
        if baseline_perf.fio_randwrite_iops > 0 and perf.fio_randwrite_iops > 0:
            io_drop = max(0.0, (baseline_perf.fio_randwrite_iops - perf.fio_randwrite_iops) / baseline_perf.fio_randwrite_iops)
            io_penalty = min(15.0, io_drop * 30.0)

        axis4 = round(max(0.0, 100.0 - (http_penalty + rss_penalty + cpu_penalty + io_penalty)), 2)

    overall = round(0.45 * axis1 + 0.20 * axis2 + 0.20 * axis3 + 0.15 * axis4, 2)

    return ContenderScorecard(
        contender_id=contender_id,
        contender_label=contender_label,
        snapshot=snapshot,
        run_started_utc=run_started_utc,
        run_ended_utc=run_ended_utc,
        axis1_efficacy=axis1,
        axis2_fp_resilience=axis2,
        axis3_latency_containment=axis3,
        axis4_overhead=axis4,
        overall_score=overall,
        gate_status=gate_status,  # type: ignore[arg-type]
        gate_reasons=gate_reasons or ["All AMTSO/WCP false-positive gates passed"],
        domain_scores=domain_scores,
        perf=perf,
        compliance_index=perf.lynis_hardening_index,
        case_results=case_results,
    )
