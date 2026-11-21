"""System overhead, HTTP latency (p50/p95/p99), deterministic CPU & fsync I/O runner."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from vgt_hardred.adapters.base import ContenderAdapter
from vgt_hardred.models import PerfMetrics
from vgt_hardred.vm_control import VMController


def run_perf_domain(
    vm: VMController,
    adapter: ContenderAdapter,
    netbench_bin: Path,
    hardening_index: int,
    lsm_active: list[str],
) -> PerfMetrics:
    metrics = PerfMetrics(lynis_hardening_index=hardening_index, lsm_active=lsm_active)

    # 1. HTTP throughput & tail latency from host -> eth1 (:80/index.php)
    if netbench_bin.is_file():
        proc = subprocess.run(
            [
                str(netbench_bin),
                "http-bench",
                "-url",
                f"{vm.cfg.http_base_url}/index.php",
                "-requests",
                "36",
                "-concurrency",
                "8",
                "-timeout-ms",
                "5000",
            ],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        if proc.stdout.strip():
            try:
                hb = json.loads(proc.stdout)
                metrics.http_rps = float(hb.get("rps", 0.0))
                metrics.http_p50_ms = float(hb.get("p50_ms", 0.0))
                metrics.http_p95_ms = float(hb.get("p95_ms", 0.0))
                metrics.http_p99_ms = float(hb.get("p99_ms", 0.0))
                metrics.http_ok = int(hb.get("ok_2xx", 0))
                metrics.http_errors = int(hb.get("transport_errors", 0)) + int(hb.get("server_5xx", 0))
            except Exception:
                pass

    # 2. Sample security processes RSS/CPU
    rss, cpu, used_mib = vm.read_process_stats(adapter.service_names())
    metrics.security_rss_mib = rss
    metrics.security_cpu_pct = cpu
    metrics.system_mem_used_mib = used_mib

    # 3. Uniform deterministic CPU + 4KB fsync random-write microbench across all 4 SUTs
    io_py = r'''
import json, os, time

t0 = time.perf_counter()
cnt = 0
for n in range(2, 24000):
    ok = True
    for d in range(2, int(n**0.5) + 1):
        if n % d == 0:
            ok = False
            break
    if ok:
        cnt += 1
dt_cpu = max(0.001, time.perf_counter() - t0)
eps = round(cnt / dt_cpu, 2)

fio_dir = "/tmp/hardred-sandbox/fio"
os.makedirs(fio_dir, exist_ok=True)
p = os.path.join(fio_dir, "bench.bin")
lat = []
block = b"VGT" * 1365 + b"X"
fd = os.open(p, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
t_all = time.perf_counter()
for i in range(400):
    t1 = time.perf_counter()
    os.lseek(fd, (i * 4096) % (1024 * 1024), os.SEEK_SET)
    os.write(fd, block)
    os.fsync(fd)
    lat.append((time.perf_counter() - t1) * 1000.0)
dt_all = max(0.001, time.perf_counter() - t_all)
os.close(fd)
lat.sort()

print(json.dumps({
    "sysbench_eps": eps,
    "fio_iops": round(400.0 / dt_all, 2),
    "fio_p99_ms": round(lat[int(0.99 * len(lat)) - 1], 3),
}))
'''
    rc, out, _ = vm.ssh("python3 -", timeout_sec=60, stdin_text=io_py)
    if rc == 0 and out.strip():
        try:
            d = json.loads(out.strip().splitlines()[-1])
            metrics.sysbench_events_per_sec = float(d.get("sysbench_eps", 0.0))
            metrics.fio_randwrite_iops = float(d.get("fio_iops", 0.0))
            metrics.fio_randwrite_lat_p99_ms = float(d.get("fio_p99_ms", 0.0))
        except Exception:
            pass

    return metrics
