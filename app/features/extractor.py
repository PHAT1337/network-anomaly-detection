"""Flow -> feature rows. Window features are *trailing* (causal): a flow only
sees the past, so batch replay and live streaming yield identical values."""
from __future__ import annotations

import math
from bisect import bisect_left
from collections import defaultdict
from typing import Iterable

from app.features.schema import FEATURE_NAMES
from app.ingestion.models import Flow

FAILED_STATES = {"S0", "REJ", "RSTO", "RSTR"}


def _flow_features(f: Flow) -> dict[str, float]:
    pkts = f.fwd_packets + f.bwd_packets
    total = f.fwd_bytes + f.bwd_bytes
    if len(f.pkt_sizes) > 1:
        m = sum(f.pkt_sizes) / len(f.pkt_sizes)
        var = sum((s - m) ** 2 for s in f.pkt_sizes) / len(f.pkt_sizes)
    else:
        var = 0.0
    if f.iats:
        im = sum(f.iats) / len(f.iats)
        istd = math.sqrt(sum((x - im) ** 2 for x in f.iats) / len(f.iats))
    else:
        im = istd = 0.0
    return {
        "duration": f.ts_end - f.ts_start,
        "fwd_packets": f.fwd_packets,
        "bwd_packets": f.bwd_packets,
        "fwd_bytes": f.fwd_bytes,
        "bwd_bytes": f.bwd_bytes,
        "mean_pkt_size": total / pkts if pkts else 0.0,
        "pkt_size_var": var,
        "iat_mean": im,
        "iat_std": istd,
        "byte_ratio": f.fwd_bytes / total if total else 0.0,
        "is_failed": 1.0 if f.state in FAILED_STATES else 0.0,
    }


def extract_features(flows: Iterable[Flow], window_s: float = 60.0) -> list[dict]:
    """Return one feature dict per flow, ordered by ``ts_start``.

    Window covers [ts_start - window_s, ts_start] for the same src_ip and
    includes the current flow.
    """
    if window_s <= 0:
        raise ValueError("window_s must be > 0")
    ordered = sorted(flows, key=lambda f: (f.ts_start, f.src_ip, f.dst_ip, f.dst_port))
    by_src: dict[str, list[int]] = defaultdict(list)
    for i, f in enumerate(ordered):
        by_src[f.src_ip].append(i)

    rows: list[dict] = []
    pos_in_src: dict[str, int] = defaultdict(int)
    for f in ordered:
        idxs = by_src[f.src_ip]
        k = pos_in_src[f.src_ip]
        pos_in_src[f.src_ip] += 1
        starts = [ordered[j].ts_start for j in idxs[: k + 1]]
        lo = bisect_left(starts, f.ts_start - window_s)
        win = [ordered[j] for j in idxs[lo : k + 1]]
        row = _flow_features(f)
        row.update(
            win_conn_count=float(len(win)),
            win_distinct_dst_ports=float(len({w.dst_port for w in win})),
            win_distinct_dst_hosts=float(len({w.dst_ip for w in win})),
            win_failed_ratio=sum(w.state in FAILED_STATES for w in win) / len(win),
            src_ip=f.src_ip, dst_ip=f.dst_ip, ts_start=f.ts_start, label=f.label,
        )
        rows.append(row)
    return rows


assert set(_flow_features.__annotations__) <= {"f", "return"}  # sanity: no hidden state
__all__ = ["extract_features", "FEATURE_NAMES"]
