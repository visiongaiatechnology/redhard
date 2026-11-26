"""Baseline (unprotected clean Ubuntu HWE 7.0) adapter."""

from __future__ import annotations

from datetime import datetime, timezone

from vgt_hardred.adapters.base import AdapterCursor, TelemetryVerdict
from vgt_hardred.models import GroundTruthCase
from vgt_hardred.vm_control import VMController


class BaselineAdapter:
    contender_id = "baseline"

    def __init__(self, vm: VMController) -> None:
        self.vm = vm

    def service_names(self) -> list[str]:
        return ["nginx", "php8.3-fpm"]

    def prepare(self) -> None:
        self.vm.ensure_sandboxes()
        self.vm.measure_clock_offset(force_refresh=True)

    def clear_attacker_blocks(self) -> None:
        return

    def capture_cursor(self) -> AdapterCursor:
        return AdapterCursor(
            captured_utc=datetime.now(timezone.utc).isoformat(),
            vm_clock_offset=self.vm.clock_offset(),
        )

    def collect_since(
        self,
        cursor: AdapterCursor,
        case: GroundTruthCase,
        started_utc: str,
        settle_sec: float = 0.0,
    ) -> TelemetryVerdict:
        return TelemetryVerdict(
            detected=False,
            context_maturity=0,
            ttfa_ms=None,
            evidence_summary="baseline unprotected webstack (no security daemon)",
            raw_alerts=[],
        )
