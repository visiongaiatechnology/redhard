"""Typed exception hierarchy with explicit disclosure and fail-closed boundaries."""

from __future__ import annotations


class HardRedError(Exception):
    """Base error for VGT HardRed Test."""


class ValidationError(HardRedError):
    """Raised when configuration, target identifiers, or CLI arguments fail validation."""


class SecurityBoundaryError(HardRedError):
    """Raised when a path-jail, sandbox boundary, or non-allowlisted target check fails."""


class TransportError(HardRedError):
    """Raised when SSH, SCP, HTTP, or VBoxManage execution fails or times out."""


class BenchmarkError(HardRedError):
    """Raised when a benchmark probe or adapter encounters an unrecoverable runtime failure."""
