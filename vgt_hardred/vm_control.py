"""Fail-closed VirtualBox snapshot manager and NAT SSH/SCP control plane."""

from __future__ import annotations

import os
import posixpath
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from vgt_hardred.errors import SecurityBoundaryError, TransportError, ValidationError

_SNAPSHOT_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
_SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
_SAFE_REMOTE_PREFIXES = ("/tmp/hardred-work", "/tmp/hardred-sandbox", "/dev/shm/hardred-sandbox")


def validate_snapshot_name(name: str) -> str:
    if not _SNAPSHOT_RE.fullmatch(name):
        raise ValidationError(f"Invalid snapshot identifier: {name!r}")
    return name


def validate_remote_path(path: str) -> str:
    if not path or "\x00" in path or any(ch in path for ch in ";|&$`\n\r"):
        raise SecurityBoundaryError(f"Unsafe characters in remote path: {path!r}")
    norm = posixpath.normpath(path)
    if not any(norm == prefix or norm.startswith(prefix + "/") for prefix in _SAFE_REMOTE_PREFIXES):
        raise SecurityBoundaryError(
            f"Remote path {norm!r} escapes sandbox roots {_SAFE_REMOTE_PREFIXES}"
        )
    return norm


@dataclass(frozen=True, slots=True)
class VMConfig:
    name: str
    vboxmanage: str
    ssh_exe: str
    scp_exe: str
    ssh_key: str
    control_host: str
    control_port: int
    control_user: str
    target_ip: str
    http_base_url: str
    https_base_url: str
    remote_work_dir: str
    sandbox_root: str
    shm_sandbox_root: str

    @classmethod
    def from_dict(cls, data: dict) -> VMConfig:
        required = [
            "name",
            "vboxmanage",
            "ssh_exe",
            "scp_exe",
            "ssh_key",
            "control_host",
            "control_port",
            "control_user",
            "target_ip",
            "http_base_url",
            "https_base_url",
            "remote_work_dir",
            "sandbox_root",
            "shm_sandbox_root",
        ]
        for key in required:
            if key not in data:
                raise ValidationError(f"Missing VMConfig key: {key}")
        validate_remote_path(data["remote_work_dir"])
        validate_remote_path(data["sandbox_root"])
        validate_remote_path(data["shm_sandbox_root"])
        return cls(
            name=str(data["name"]),
            vboxmanage=str(data["vboxmanage"]),
            ssh_exe=str(data["ssh_exe"]),
            scp_exe=str(data["scp_exe"]),
            ssh_key=str(data["ssh_key"]),
            control_host=str(data["control_host"]),
            control_port=int(data["control_port"]),
            control_user=str(data["control_user"]),
            target_ip=str(data["target_ip"]),
            http_base_url=str(data["http_base_url"]).rstrip("/"),
            https_base_url=str(data["https_base_url"]).rstrip("/"),
            remote_work_dir=posixpath.normpath(data["remote_work_dir"]),
            sandbox_root=posixpath.normpath(data["sandbox_root"]),
            shm_sandbox_root=posixpath.normpath(data["shm_sandbox_root"]),
        )


class VMController:
    """Executes bounded, non-interactive commands on the isolated pentest VM via NAT SSH."""

    def __init__(self, cfg: VMConfig) -> None:
        self.cfg = cfg

    def _run_local(self, args: list[str], timeout_sec: int = 120) -> subprocess.CompletedProcess[str]:
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_sec,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TransportError(f"Command timed out after {timeout_sec}s: {args[0]}") from exc
        except OSError as exc:
            raise TransportError(f"Failed executing {args[0]}: {exc}") from exc
        return proc

    def ssh(
        self,
        command: str,
        timeout_sec: int = 60,
        stdin_text: str | None = None,
    ) -> tuple[int, str, str]:
        args = [
            self.cfg.ssh_exe,
            "-i",
            self.cfg.ssh_key,
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=5",
            "-o",
            "ServerAliveCountMax=2",
            "-p",
            str(self.cfg.control_port),
            f"{self.cfg.control_user}@{self.cfg.control_host}",
            command,
        ]
        try:
            proc = subprocess.run(
                args,
                input=stdin_text,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_sec,
                check=False,
            )
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            raise TransportError(f"SSH command timed out after {timeout_sec}s") from exc
        except OSError as exc:
            raise TransportError(f"SSH transport failure: {exc}") from exc

    def scp_push(self, local_path: Path, remote_path: str, timeout_sec: int = 120) -> None:
        safe_remote = validate_remote_path(remote_path)
        if not local_path.is_file():
            raise ValidationError(f"Local upload file not found: {local_path}")
        parent = posixpath.dirname(safe_remote)
        rc, _, err = self.ssh(f"mkdir -p {parent}", timeout_sec=15)
        if rc != 0:
            raise TransportError(f"Failed preparing remote directory {parent}: {err}")
        args = [
            self.cfg.scp_exe,
            "-i",
            self.cfg.ssh_key,
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-P",
            str(self.cfg.control_port),
            str(local_path),
            f"{self.cfg.control_user}@{self.cfg.control_host}:{safe_remote}",
        ]
        proc = self._run_local(args, timeout_sec=timeout_sec)
        if proc.returncode != 0:
            raise TransportError(f"SCP push failed ({proc.returncode}): {proc.stderr.strip()}")

    def wait_for_ssh(self, max_wait_sec: int = 120) -> None:
        deadline = time.monotonic() + max_wait_sec
        last_err = ""
        while time.monotonic() < deadline:
            try:
                rc, out, err = self.ssh("echo HARDRED_SSH_READY", timeout_sec=10)
                if rc == 0 and "HARDRED_SSH_READY" in out:
                    return
                last_err = err.strip() or f"rc={rc}"
            except TransportError as exc:
                last_err = str(exc)
            time.sleep(2.5)
        raise TransportError(f"VM SSH failed to become ready within {max_wait_sec}s: {last_err}")

    def restore_and_boot_snapshot(self, snapshot_name: str, settle_sec: int = 12) -> None:
        snap = validate_snapshot_name(snapshot_name)
        vm = self.cfg.name
        # Check current VM state; power off if running so snapshot restore never races.
        info = self._run_local([self.cfg.vboxmanage, "showvminfo", vm, "--machinereadable"], timeout_sec=20)
        if info.returncode != 0:
            raise TransportError(f"VBoxManage showvminfo failed: {info.stderr.strip()}")
        if 'VMState="running"' in info.stdout or 'VMState="paused"' in info.stdout:
            stop = self._run_local([self.cfg.vboxmanage, "controlvm", vm, "poweroff"], timeout_sec=45)
            if stop.returncode != 0:
                raise TransportError(f"Failed powering off VM {vm}: {stop.stderr.strip()}")
            time.sleep(2.0)

        rest = self._run_local([self.cfg.vboxmanage, "snapshot", vm, "restore", snap], timeout_sec=90)
        if rest.returncode != 0:
            raise TransportError(f"Snapshot restore {snap} failed: {rest.stderr.strip()}")

        start = self._run_local([self.cfg.vboxmanage, "startvm", vm, "--type", "headless"], timeout_sec=60)
        if start.returncode != 0:
            raise TransportError(f"Failed starting VM {vm}: {start.stderr.strip()}")

        self.wait_for_ssh(max_wait_sec=120)
        # Ensure VirtualBox NAT forwarding rules exist if snapshot lacked ssh-mgmt.
        time.sleep(settle_sec)

    def ensure_sandboxes(self) -> None:
        cmd = (
            f"sudo mkdir -p {self.cfg.remote_work_dir} {self.cfg.sandbox_root} {self.cfg.shm_sandbox_root} "
            f"&& sudo chown -R {self.cfg.control_user}:{self.cfg.control_user} {self.cfg.remote_work_dir} {self.cfg.sandbox_root} {self.cfg.shm_sandbox_root} "
            f"&& sudo chmod 755 {self.cfg.remote_work_dir} {self.cfg.sandbox_root} {self.cfg.shm_sandbox_root}"
        )
        rc, _, err = self.ssh(cmd, timeout_sec=15)
        if rc != 0:
            raise TransportError(f"Failed creating remote sandboxes: {err}")

    def read_process_stats(self, service_names: list[str]) -> tuple[float, float, float]:
        """Return (rss_mib, cpu_pct, system_mem_used_mib) sampled cleanly inside the VM."""
        for svc in service_names:
            if not _SERVICE_RE.fullmatch(svc):
                raise ValidationError(f"Invalid service pattern: {svc!r}")
        joined = "|".join(re.escape(s.split(".")[0]) for s in service_names)
        py_one_liner = (
            "import subprocess, json; "
            "ps = subprocess.check_output(['ps', '-eo', 'pid,pcpu,rss,comm', '--no-headers'], text=True); "
            f"import re; pat = re.compile(r'{joined}', re.I); "
            "rss = 0; cpu = 0.0; "
            "\nfor line in ps.splitlines():\n"
            "  parts = line.split(None, 3)\n"
            "  if len(parts)==4 and pat.search(parts[3]): cpu += float(parts[1]); rss += int(parts[2])\n"
            "mem = subprocess.check_output(['free', '-m'], text=True).splitlines()[1].split(); "
            "print(json.dumps({'rss_mib': round(rss/1024.0, 2), 'cpu_pct': round(cpu, 2), 'sys_used_mib': float(mem[2])}))"
        )
        rc, out, err = self.ssh(f"python3 -c { _shell_quote(py_one_liner) }", timeout_sec=15)
        if rc != 0:
            return 0.0, 0.0, 0.0
        import json

        data = json.loads(out.strip().splitlines()[-1])
        return float(data["rss_mib"]), float(data["cpu_pct"]), float(data["sys_used_mib"])


def _shell_quote(text: str) -> str:
    return "'" + text.replace("'", "'\"'\"'") + "'"
