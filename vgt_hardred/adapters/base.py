"""Base telemetry adapter interface and deterministic Context Maturity classifier."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from vgt_hardred.models import GroundTruthCase


@dataclass(slots=True)
class AdapterCursor:
    captured_utc: str
    state: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class TelemetryVerdict:
    detected: bool
    context_maturity: int
    ttfa_ms: float | None
    evidence_summary: str
    raw_alerts: list[dict[str, Any]] = field(default_factory=list)


class ContenderAdapter(Protocol):
    contender_id: str

    def prepare(self) -> None:
        ...

    def clear_attacker_blocks(self) -> None:
        ...

    def capture_cursor(self) -> AdapterCursor:
        ...

    def collect_since(
        self,
        cursor: AdapterCursor,
        case: GroundTruthCase,
        started_utc: str,
        settle_sec: float = 1.5,
    ) -> TelemetryVerdict:
        ...

    def service_names(self) -> list[str]:
        ...


def parse_iso_utc(value: str | None) -> float | None:
    if not value:
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


def compute_context_maturity(alerts: list[dict[str, Any]], has_lineage_or_chain: bool = False) -> int:
    if not alerts:
        return 0
    if has_lineage_or_chain:
        return 3
    rich_keys = {"pid", "exe", "process", "uri", "src_ip", "remote_addr", "mitre", "rule_id", "rule", "target", "path", "cmdline"}
    for alert in alerts:
        flat_keys = {k.lower() for k in alert.keys()}
        if flat_keys & {"lineage", "parent_pid", "ppid", "attack_story", "chain_hash", "evidence_id", "correlation_id"}:
            return 3
    for alert in alerts:
        flat_keys = {k.lower() for k in alert.keys()}
        if len(flat_keys & rich_keys) >= 2:
            return 2
    return 1
