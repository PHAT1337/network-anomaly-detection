"""Single source of truth for feature definitions (training == inference)."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FeatureSpec:
    name: str
    description: str
    model_input: bool = True  # False => identifier/metadata, excluded from ML (leakage/overfit guard)


FEATURES: tuple[FeatureSpec, ...] = (
    FeatureSpec("duration", "Flow duration in seconds"),
    FeatureSpec("fwd_packets", "Packets src->dst"),
    FeatureSpec("bwd_packets", "Packets dst->src"),
    FeatureSpec("fwd_bytes", "Bytes src->dst"),
    FeatureSpec("bwd_bytes", "Bytes dst->src"),
    FeatureSpec("mean_pkt_size", "Total bytes / total packets"),
    FeatureSpec("pkt_size_var", "Population variance of packet sizes (0 if unavailable)"),
    FeatureSpec("iat_mean", "Mean inter-arrival time (s, 0 if unavailable)"),
    FeatureSpec("iat_std", "Std of inter-arrival time (s, 0 if unavailable)"),
    FeatureSpec("byte_ratio", "fwd_bytes / (fwd_bytes + bwd_bytes)"),
    FeatureSpec("is_failed", "1 if state in {S0, REJ, RSTO, RSTR}"),
    FeatureSpec("win_conn_count", "Trailing-window connections from same src"),
    FeatureSpec("win_distinct_dst_ports", "Trailing-window distinct dst ports from same src"),
    FeatureSpec("win_distinct_dst_hosts", "Trailing-window distinct dst hosts from same src"),
    FeatureSpec("win_failed_ratio", "Trailing-window failed-connection ratio from same src"),
    # Metadata: kept for evidence/alerts, never fed to models.
    FeatureSpec("src_ip", "Source IP", model_input=False),
    FeatureSpec("dst_ip", "Destination IP", model_input=False),
    FeatureSpec("ts_start", "Flow start time", model_input=False),
    FeatureSpec("label", "Ground-truth label (evaluation only)", model_input=False),
)

FEATURE_NAMES: tuple[str, ...] = tuple(f.name for f in FEATURES)
MODEL_FEATURES: tuple[str, ...] = tuple(f.name for f in FEATURES if f.model_input)
