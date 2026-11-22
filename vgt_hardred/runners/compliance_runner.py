"""Compliance & system hardening posture runner (Lynis + Linux LSM check)."""

from __future__ import annotations

import re
import tarfile
import tempfile
from pathlib import Path
from typing import Any

from vgt_hardred.vm_control import VMController


def run_compliance_domain(
    vm: VMController,
    lynis_dir: Path | None,
) -> tuple[int, list[str], dict[str, Any]]:
    """Run Lynis quick audit + kernel LSM inspection on target VM."""
    # Check active Linux Security Modules
    rc_lsm, out_lsm, _ = vm.ssh("cat /sys/kernel/security/lsm 2>/dev/null || true", timeout_sec=10)
    lsm_active = [x.strip() for x in out_lsm.strip().split(",") if x.strip()] if rc_lsm == 0 else []

    hardening_index = 0
    warnings_count = 0
    suggestions_count = 0
    lynis_ran = False

    if lynis_dir and (lynis_dir / "lynis").is_file():
        with tempfile.TemporaryDirectory() as tmp:
            tgz = Path(tmp) / "lynis.tar.gz"
            with tarfile.open(tgz, "w:gz") as tf:
                for sub in ("lynis", "default.prf", "include", "db"):
                    src = lynis_dir / sub
                    if src.exists():
                        tf.add(src, arcname=f"lynis/{sub}")
            remote_tgz = f"{vm.cfg.remote_work_dir}/lynis.tar.gz"
            vm.scp_push(tgz, remote_tgz, timeout_sec=60)
            rc, out, err = vm.ssh(
                f"cd {vm.cfg.remote_work_dir} && rm -rf lynis && tar -xzf lynis.tar.gz && "
                f"sudo mkdir -p lynis/plugins && "
                f"sudo chown -R 0:0 lynis && sudo chmod 755 lynis/lynis && sudo chmod -R go-w lynis && "
                f"sudo /bin/sh -c 'cd {vm.cfg.remote_work_dir}/lynis && /bin/sh ./lynis audit system --quick --no-colors --quiet </dev/null' 2>&1 || true; "
                f"sudo grep -E 'hardening_index|warning\\[\\]|suggestion\\[\\]' /var/log/lynis-report.dat 2>/dev/null || true",
                timeout_sec=180,
            )
            lynis_ran = True
            m_idx = re.search(r"hardening_index=(\d+)", out)
            if not m_idx:
                m_idx = re.search(r"Hardening index\s*:\s*\[?\s*(\d+)", out)
            if m_idx:
                hardening_index = int(m_idx.group(1))
            warnings_count = len(re.findall(r"warning\[\]=", out))
            suggestions_count = len(re.findall(r"suggestion\[\]=", out))

    return hardening_index, lsm_active, {
        "lynis_ran": lynis_ran,
        "hardening_index": hardening_index,
        "warnings": warnings_count,
        "suggestions": suggestions_count,
        "lsm_active": lsm_active,
    }
