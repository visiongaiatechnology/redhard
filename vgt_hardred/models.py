"""Strict data models for ground-truth cases, telemetry events, 4-axis scoring, and exports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

DomainName = Literal[
    "hardred-waf",
    "hardred-netids",
    "hardred-endpoint",
    "hardred-malware",
    "hardred-compliance",
    "hardred-perf",
]
Polarity = Literal["attack", "benign", "posture", "perf"]


@dataclass(slots=True)
class GroundTruthCase:
    case_id: str
    domain: DomainName
    category: str
    title: str
    polarity: Polarity
    mitre_technique: str
    mitre_tactic: str
    tool_source: str
    expected_prevention: bool
    severity: Literal["info", "low", "medium", "high", "critical"] = "high"


@dataclass(slots=True)
class CaseResult:
    case: GroundTruthCase
    started_utc: str
    ended_utc: str
    duration_ms: float
    detected: bool
    prevented: bool
    context_maturity: int  # 0=Blind, 1=Generic, 2=Telemetry, 3=Correlation/Lineage
    ttfa_ms: float | None
    pre_kill_damage: int | None
    pre_kill_total: int | None
    http_status: int | None = None
    exit_code: int | None = None
    evidence_summary: str = ""
    raw_alerts: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["case"] = asdict(self.case)
        return payload


@dataclass(slots=True)
class PerfMetrics:
    http_rps: float = 0.0
    http_p50_ms: float = 0.0
    http_p95_ms: float = 0.0
    http_p99_ms: float = 0.0
    http_ok: int = 0
    http_errors: int = 0
    sysbench_events_per_sec: float = 0.0
    fio_randwrite_iops: float = 0.0
    fio_randwrite_lat_p99_ms: float = 0.0
    security_rss_mib: float = 0.0
    security_cpu_pct: float = 0.0
    system_mem_used_mib: float = 0.0
    lynis_hardening_index: int = 0
    lsm_active: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DomainScore:
    domain: str
    attack_total: int
    benign_total: int
    detected_tp: int
    prevented_tp: int
    detection_fp: int
    protection_fp: int
    detection_tpr: float
    prevention_tpr: float
    detection_fpr: float
    protection_fpr: float
    balanced_accuracy: float
    youden_j: float
    avg_context_maturity: float
    median_ttfa_ms: float | None
    avg_damage_ratio: float | None
    domain_score: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ContenderScorecard:
    contender_id: str
    contender_label: str
    snapshot: str
    run_started_utc: str
    run_ended_utc: str
    axis1_efficacy: float
    axis2_fp_resilience: float
    axis3_latency_containment: float
    axis4_overhead: float
    overall_score: float
    gate_status: Literal["PASS", "CONDITIONAL", "FAIL"]
    gate_reasons: list[str]
    domain_scores: dict[str, DomainScore]
    perf: PerfMetrics
    compliance_index: int
    case_results: list[CaseResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contender_id": self.contender_id,
            "contender_label": self.contender_label,
            "snapshot": self.snapshot,
            "run_started_utc": self.run_started_utc,
            "run_ended_utc": self.run_ended_utc,
            "axis1_efficacy": self.axis1_efficacy,
            "axis2_fp_resilience": self.axis2_fp_resilience,
            "axis3_latency_containment": self.axis3_latency_containment,
            "axis4_overhead": self.axis4_overhead,
            "overall_score": self.overall_score,
            "gate_status": self.gate_status,
            "gate_reasons": self.gate_reasons,
            "domain_scores": {k: v.to_dict() for k, v in self.domain_scores.items()},
            "perf": self.perf.to_dict(),
            "compliance_index": self.compliance_index,
            "case_results": [c.to_dict() for c in self.case_results],
        }
