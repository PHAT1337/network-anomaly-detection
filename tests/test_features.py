import pytest

from app.features.extractor import extract_features
from app.features.schema import FEATURE_NAMES, MODEL_FEATURES
from app.ingestion.models import Flow, ValidationError
from app.ingestion.synthetic import generate


def mk(**kw):
    base = dict(ts_start=0.0, ts_end=1.0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                src_port=1234, dst_port=80, proto="tcp", fwd_packets=2,
                bwd_packets=2, fwd_bytes=200, bwd_bytes=600, state="SF")
    base.update(kw)
    return Flow(**base)


@pytest.mark.parametrize("bad", [
    dict(src_ip="not-an-ip"), dict(dst_port=70000), dict(ts_end=-1.0),
    dict(fwd_bytes=-5), dict(proto="weird"), dict(state="XX"),
    dict(ts_start=float("nan")),
])
def test_malformed_flows_rejected(bad):
    with pytest.raises(ValidationError):
        mk(**bad)


def test_basic_features():
    r = extract_features([mk(pkt_sizes=(100, 300), iats=(0.1, 0.3))])[0]
    assert r["duration"] == 1.0
    assert r["mean_pkt_size"] == 200.0
    assert r["pkt_size_var"] == 10000.0
    assert r["byte_ratio"] == 0.25
    assert r["is_failed"] == 0.0


def test_zero_packets_no_division_error():
    r = extract_features([mk(fwd_packets=0, bwd_packets=0, fwd_bytes=0, bwd_bytes=0)])[0]
    assert r["mean_pkt_size"] == 0.0 and r["byte_ratio"] == 0.0


def test_window_is_causal_no_future_leakage():
    flows = [mk(ts_start=t, ts_end=t + 1, dst_port=p) for t, p in [(0, 1), (10, 2), (20, 3)]]
    rows = extract_features(flows, window_s=60)
    assert [r["win_conn_count"] for r in rows] == [1, 2, 3]
    assert [r["win_distinct_dst_ports"] for r in rows] == [1, 2, 3]


def test_window_expires_old_flows():
    flows = [mk(ts_start=0, ts_end=1), mk(ts_start=100, ts_end=101)]
    assert extract_features(flows, window_s=60)[1]["win_conn_count"] == 1


def test_window_is_per_source():
    flows = [mk(src_ip="10.0.0.1"), mk(src_ip="10.0.0.3", ts_start=1, ts_end=2)]
    assert all(r["win_conn_count"] == 1 for r in extract_features(flows))


def test_invalid_window_rejected():
    with pytest.raises(ValueError):
        extract_features([], window_s=0)


def test_synthetic_is_deterministic():
    assert generate(seed=7) == generate(seed=7)
    assert generate(seed=7) != generate(seed=8)


def test_scan_fixture_stands_out_from_normal():
    rows = extract_features(generate())
    scan = [r for r in rows if r["label"] == "scan_sim"][-1]
    normal = [r for r in rows if r["label"] == "normal"]
    assert scan["win_distinct_dst_ports"] > 50
    assert scan["win_failed_ratio"] == 1.0
    assert max(r["win_distinct_dst_ports"] for r in normal) <= 3
    # An unusual-but-legit case: normal rows are never fully failed.
    assert all(r["win_failed_ratio"] == 0.0 for r in normal)


def test_schema_matches_output_and_excludes_identifiers():
    row = extract_features([mk()])[0]
    assert set(row) == set(FEATURE_NAMES)
    assert not {"src_ip", "dst_ip", "ts_start", "label"} & set(MODEL_FEATURES)
