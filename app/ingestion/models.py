"""Canonical flow record. All ingestion adapters (PCAP, Zeek, NetFlow, datasets,
synthetic) must emit ``Flow`` so downstream code never sees source formats."""
from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass, field

VALID_PROTOS = {"tcp", "udp", "icmp", "other"}
# Zeek-style connection states.
VALID_STATES = {"SF", "S0", "REJ", "RSTO", "RSTR", "OTH"}


class ValidationError(ValueError):
    """Raised when an imported record is malformed (imports are untrusted)."""


@dataclass(frozen=True, slots=True)
class Flow:
    ts_start: float
    ts_end: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    fwd_packets: int
    bwd_packets: int
    fwd_bytes: int
    bwd_bytes: int
    state: str = "OTH"
    pkt_sizes: tuple[int, ...] = field(default_factory=tuple)  # optional
    iats: tuple[float, ...] = field(default_factory=tuple)     # optional
    label: str | None = None  # ground truth if known; NEVER a model input

    def __post_init__(self) -> None:
        for ip in (self.src_ip, self.dst_ip):
            try:
                ipaddress.ip_address(ip)
            except ValueError as exc:
                raise ValidationError(f"invalid IP: {ip!r}") from exc
        for name in ("ts_start", "ts_end"):
            v = getattr(self, name)
            if not isinstance(v, (int, float)) or not math.isfinite(v):
                raise ValidationError(f"{name} must be a finite number")
        if self.ts_end < self.ts_start:
            raise ValidationError("ts_end precedes ts_start")
        for name in ("src_port", "dst_port"):
            if not 0 <= getattr(self, name) <= 65535:
                raise ValidationError(f"{name} out of range")
        for name in ("fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes"):
            if getattr(self, name) < 0:
                raise ValidationError(f"{name} must be >= 0")
        if self.proto not in VALID_PROTOS:
            raise ValidationError(f"unknown proto: {self.proto!r}")
        if self.state not in VALID_STATES:
            raise ValidationError(f"unknown state: {self.state!r}")
