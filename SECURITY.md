# Security Policy & Responsible Benchmark Use

## 1. Authorized Lab Use Only

**VGT HardRed (`RedHard`)** is a defensive security benchmark and evaluation framework designed to measure the detection accuracy, active prevention capability, false-positive resilience, and performance overhead of Linux security software.

- **Never execute VGT HardRed against production systems or networks you do not own or lack explicit written authorization to test.**
- All endpoint probes (`hardred-probe`) enforce strict path jailing (`/tmp/hardred-sandbox` and `/dev/shm/hardred-sandbox`) and fail closed on any path traversal, symlink escape, or out-of-sandbox target.
- Always run target virtual machines on an isolated Host-Only / Lab network segment.

## 2. Reporting Security Vulnerabilities

If you discover a security issue in `VGT HardRed` (such as a sandbox jail bypass in `hardred-probe`, command injection in an adapter, or unsafe file handling):

- **Email:** `security@visiongaiatechnology.de`
- Please include a minimal reproduction, affected file/line reference, and impact description.
- Do not open public GitHub issues for exploitable security bugs before a fix is released.
