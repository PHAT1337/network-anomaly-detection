"""Seeded synthetic traffic for tests/demos. The 'scan_sim' pattern is a
labeled *detection test fixture* (flow metadata only; no packets are sent)."""
from __future__ import annotations

import random

from app.ingestion.models import Flow


def generate(seed: int = 42, n_normal: int = 200, with_scan: bool = True,
             duration_s: float = 300.0) -> list[Flow]:
    rng = random.Random(seed)
    clients = [f"10.0.0.{i}" for i in range(10, 20)]
    servers = [("10.0.1.5", 443), ("10.0.1.6", 80), ("10.0.1.7", 53)]
    flows: list[Flow] = []
    for _ in range(n_normal):
        t = rng.uniform(0, duration_s)
        dst, port = rng.choice(servers)
        fp, bp = rng.randint(3, 40), rng.randint(3, 60)
        sizes = tuple(rng.randint(60, 1400) for _ in range(min(fp + bp, 20)))
        flows.append(Flow(
            ts_start=t, ts_end=t + rng.uniform(0.1, 5.0),
            src_ip=rng.choice(clients), dst_ip=dst,
            src_port=rng.randint(32768, 60999), dst_port=port,
            proto="udp" if port == 53 else "tcp",
            fwd_packets=fp, bwd_packets=bp,
            fwd_bytes=fp * rng.randint(60, 500), bwd_bytes=bp * rng.randint(100, 1200),
            state="SF", pkt_sizes=sizes,
            iats=tuple(rng.expovariate(20) for _ in range(5)), label="normal"))
    if with_scan:
        t0 = duration_s / 2
        for i in range(100):
            t = t0 + i * 0.05
            flows.append(Flow(
                ts_start=t, ts_end=t + 0.01, src_ip="10.0.0.99", dst_ip="10.0.1.5",
                src_port=50000 + i, dst_port=1 + i * 7, proto="tcp",
                fwd_packets=1, bwd_packets=0, fwd_bytes=60, bwd_bytes=0,
                state="S0", label="scan_sim"))
    return flows
