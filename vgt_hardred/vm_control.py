"""Fail-closed VirtualBox snapshot manager and NAT SSH/SCP control plane."""

from __future__ import annotations

import json
import os
import posixpath
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from vgt_hardred.errors import SecurityBoundaryError, TransportError, ValidationError

_SNAPSHOT_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
_SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,64}$")
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
    attacker_source_ip: str = "192.168.56.1"

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
            attacker_source_ip=str(data.get("attacker_source_ip") or "192.168.56.1"),
        )


class VMController:
    """Executes bounded, non-interactive commands on the isolated pentest VM via NAT SSH."""

    def __init__(self, cfg: VMConfig) -> None:
        self.cfg = cfg
        self._clock_offset: float | None = None
        self._clock_offset_rtt_ms: float | None = None
        self._clock_offset_at: float = 0.0

    def _invalidate_clock_offset(self) -> None:
        self._clock_offset = None
        self._clock_offset_rtt_ms = None
        self._clock_offset_at = 0.0

    def _measure_clock_offset_pipe(self, pings: int = 5) -> float | None:
        """Open one persistent SSH stdio channel and ping over it (<3ms RTT, zero handshake skew)."""
        if os.environ.get("VGT_HARDRED_DISABLE_PIPE_CLOCK"):
            return None
        py_remote = (
            "import sys, time\n"
            "print('READY', flush=True)\n"
            "for line in sys.stdin:\n"
            "    print(f'{time.time():.6f}', flush=True)\n"
        )
        args = [
            self.cfg.ssh_exe,
            "-T",
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
            "-p",
            str(self.cfg.control_port),
            f"{self.cfg.control_user}@{self.cfg.control_host}",
            "python3 -u -c " + _shell_quote(py_remote),
        ]
        try:
            proc = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError:
            return None

        best_rtt: float | None = None
        best_offset: float | None = None
        try:
            assert proc.stdout is not None and proc.stdin is not None
            ready = proc.stdout.readline()
            if "READY" not in ready:
                return None
            for _ in range(max(1, min(pings, 9))):
                host_t0 = time.time()
                mono_0 = time.perf_counter()
                proc.stdin.write("P\n")
                proc.stdin.flush()
                line = proc.stdout.readline()
                mono_1 = time.perf_counter()
                if not line:
                    break
                try:
                    vm_epoch = float(line.strip())
                except ValueError:
                    continue
                rtt = max(0.0, mono_1 - mono_0)
                host_mid = host_t0 + (rtt / 2.0)
                offset = vm_epoch - host_mid
                if best_rtt is None or rtt < best_rtt:
                    best_rtt = rtt
                    best_offset = offset
            try:
                proc.stdin.close()
            except Exception:
                pass
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
            return None

        if best_offset is not None and best_rtt is not None:
            self._clock_offset = best_offset
            self._clock_offset_rtt_ms = round(best_rtt * 1000.0, 2)
            self._clock_offset_at = time.monotonic()
            return best_offset
        return None

    def measure_clock_offset(
        self,
        samples: int = 3,
        force_refresh: bool = False,
        max_age_sec: float = 20.0,
    ) -> float:
        """Estimate (vm_epoch - host_epoch) via symmetric min-RTT NTP midpoint calibration."""
        now_mono = time.monotonic()
        if (
            not force_refresh
            and self._clock_offset is not None
            and (now_mono - self._clock_offset_at) < max_age_sec
        ):
            return self._clock_offset

        # Prefer persistent open-pipe ping when ssh() is unpatched so SSH handshake latency causes zero bias.
        if getattr(self.ssh, "__func__", None) is VMController.ssh:
            pipe_off = self._measure_clock_offset_pipe(pings=max(5, int(samples)))
            if pipe_off is not None:
                return pipe_off

        best_rtt: float | None = None
        best_offset: float | None = None
        count = max(1, min(int(samples), 7))
        for _ in range(count):
            host_t0 = time.time()
            mono_0 = time.perf_counter()
            try:
                rc, out, _ = self.ssh("python3 -c 'import time; print(f\"{time.time():.6f}\")'", timeout_sec=10)
            except TransportError:
                continue
            mono_1 = time.perf_counter()
            if rc != 0 or not out.strip():
                continue
            try:
                vm_epoch = float(out.strip().splitlines()[-1])
            except ValueError:
                continue
            rtt = max(0.0, mono_1 - mono_0)
            host_mid = host_t0 + (rtt / 2.0)
            offset = vm_epoch - host_mid
            if best_rtt is None or rtt < best_rtt:
                best_rtt = rtt
                best_offset = offset

        if best_offset is not None and best_rtt is not None:
            self._clock_offset = best_offset
            self._clock_offset_rtt_ms = round(best_rtt * 1000.0, 2)
            self._clock_offset_at = time.monotonic()
            return best_offset
        return self._clock_offset if self._clock_offset is not None else 0.0

    def clock_offset(self) -> float:
        return self.measure_clock_offset()

    def ssh_timed(
        self,
        command: str,
        timeout_sec: int = 60,
        stdin_text: str | None = None,
    ) -> tuple[int, str, str, float | None]:
        """Execute an SSH command and stamp exact VM UTC epoch right before running it."""
        if stdin_text is not None:
            rc, out, err = self.ssh(command, timeout_sec=timeout_sec, stdin_text=stdin_text)
            return rc, out, err, None
        marker = "__HARDRED_VM_T0__="
        wrapped = (
            f"python3 -c 'import time; print(\"{marker}\" + f\"{{time.time():.6f}}\")' && ( {command} )"
        )
        rc, out, err = self.ssh(wrapped, timeout_sec=timeout_sec)
        vm_t0: float | None = None
        cleaned: list[str] = []
        for ln in out.splitlines():
            if ln.startswith(marker) and vm_t0 is None:
                try:
                    vm_t0 = float(ln[len(marker):].strip())
                    continue
                except ValueError:
                    pass
            cleaned.append(ln)
        return rc, "\n".join(cleaned), err, vm_t0

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
        self._invalidate_clock_offset()
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
        last_err = ""
        for attempt in range(3):
            try:
                rc, _, err = self.ssh(cmd, timeout_sec=30)
                if rc == 0:
                    return
                last_err = err
            except TransportError as exc:
                last_err = str(exc)
            if attempt < 2:
                time.sleep(3.0)
        raise TransportError(f"Failed creating remote sandboxes: {last_err}")

    def read_process_stats(self, service_names: list[str]) -> tuple[float, float, float]:
        """Return (rss_mib, cpu_pct, system_mem_used_mib) sampled cleanly inside the VM."""
        docker_prefixes: list[str] = []
        host_services: list[str] = []
        for svc in service_names:
            if not _SERVICE_RE.fullmatch(svc):
                raise ValidationError(f"Invalid service pattern: {svc!r}")
            if svc.startswith("docker:"):
                docker_prefixes.append(svc[len("docker:"):])
            else:
                host_services.append(svc)

        joined = "|".join(re.escape(s.split(".")[0]) for s in host_services)
        py_script = (
            "import subprocess, json, re\n"
            "rss = 0.0; cpu = 0.0\n"
        )
        if joined:
            py_script += (
                "ps = subprocess.check_output(['ps', '-eo', 'pid,pcpu,rss,comm', '--no-headers'], text=True)\n"
                f"pat = re.compile(r'{joined}', re.I)\n"
                "for line in ps.splitlines():\n"
                "  parts = line.split(None, 3)\n"
                "  if len(parts) == 4 and pat.search(parts[3]):\n"
                "    cpu += float(parts[1]); rss += int(parts[2]) / 1024.0\n"
            )
        if docker_prefixes:
            pref_json = json.dumps(docker_prefixes)
            py_script += (
                f"prefixes = {pref_json}\n"
                "def to_mib(val):\n"
                "  m = re.match(r'^([0-9.]+)\\s*([A-Za-z]+)$', val.strip())\n"
                "  if not m: return 0.0\n"
                "  n, u = float(m.group(1)), m.group(2).lower()\n"
                "  if u.startswith('g'): return n * 1024.0\n"
                "  if u.startswith('m'): return n\n"
                "  if u.startswith('k'): return n / 1024.0\n"
                "  return n / (1024.0 * 1024.0)\n"
                "try:\n"
                "  ds = subprocess.check_output(['sudo', 'docker', 'stats', '--no-stream', '--format', '{{.Name}}\\t{{.CPUPerc}}\\t{{.MemUsage}}'], text=True, timeout=15)\n"
                "  for line in ds.splitlines():\n"
                "    cols = line.split('\\t')\n"
                "    if len(cols) == 3 and any(cols[0].startswith(p) for p in prefixes):\n"
                "      cpu += float(cols[1].rstrip('%') or 0.0)\n"
                "      rss += to_mib(cols[2].split('/')[0])\n"
                "except Exception:\n"
                "  pass\n"
            )
        py_script += (
            "mem = subprocess.check_output(['free', '-m'], text=True).splitlines()[1].split()\n"
            "print(json.dumps({'rss_mib': round(rss, 2), 'cpu_pct': round(cpu, 2), 'sys_used_mib': float(mem[2])}))\n"
        )
        rc, out, err = self.ssh(f"python3 -c { _shell_quote(py_script) }", timeout_sec=25)
        if rc != 0 or not out.strip():
            return 0.0, 0.0, 0.0
        data = json.loads(out.strip().splitlines()[-1])
        return float(data["rss_mib"]), float(data["cpu_pct"]), float(data["sys_used_mib"])


def _shell_quote(text: str) -> str:
    return "'" + text.replace("'", "'\"'\"'") + "'"
