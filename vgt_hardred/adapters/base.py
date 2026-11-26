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
    vm_clock_offset: float = 0.0
    vm_t0_epoch: float | None = None


def effective_t0_epoch(
    started_utc: str,
    cursor: AdapterCursor | None = None,
    vm_clock_offset: float | None = None,
    t0_epoch_override: float | None = None,
) -> float:
    """Resolve the authoritative VM-synchronized start epoch (seconds) for TTFA measurement."""
    if t0_epoch_override is not None:
        return float(t0_epoch_override)
    if cursor is not None and cursor.vm_t0_epoch is not None:
        return float(cursor.vm_t0_epoch)
    base = parse_iso_utc(started_utc) or 0.0
    if base <= 0.0:
        return 0.0
    offset = vm_clock_offset if vm_clock_offset is not None else (cursor.vm_clock_offset if cursor is not None else 0.0)
    return base + float(offset)


def compute_event_ttfa_ms(
    ev_ts: float | None,
    t0_epoch: float,
    jitter_grace_sec: float = 0.020,
    integer_second_granularity: bool = False,
) -> float | None:
    """Convert event epoch timestamp into non-negative TTFA in milliseconds."""
    if ev_ts is None or ev_ts <= 0.0 or t0_epoch <= 0.0:
        return None
    if ev_ts >= (t0_epoch - jitter_grace_sec):
        return max(1.0, (ev_ts - t0_epoch) * 1000.0)
    # Logs with 1-second truncation (e.g. SafeLine / ModSecurity) falling in the exact start second
    if integer_second_granularity and int(ev_ts) == int(t0_epoch):
        frac_rem = max(0.05, 1.0 - (t0_epoch % 1.0))
        return max(25.0, min(250.0, frac_rem * 500.0))
    return None


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
