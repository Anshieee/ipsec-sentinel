"""API tests: health/models/analyze/report on a real corpus pcap."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engine" / "api"))
from app import app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(app)
SAMPLE = ROOT / "data" / "pcaps" / "synth" / "v1" / "r1" / "voip.pcap"


def _upload_copy(tmp_path, src=SAMPLE, name="voip.pcap"):
    """Isolated upload bytes: never hand the server a data/ path."""
    import shutil
    dest = tmp_path / name
    shutil.copy(src, dest)
    return dest.read_bytes()


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["models_loaded"] is True


def test_models():
    r = client.get("/models")
    assert r.status_code == 200
    body = r.json()
    assert "traffic_type" in body["fields"]
    assert body["meta"]["seed"] == 7


def test_analyze(tmp_path):
    data = _upload_copy(tmp_path)
    r = client.post("/analyze", files={"file": ("voip.pcap", data)})
    assert r.status_code == 200
    body = r.json()
    # Child suite is model-INFERRED (IKE_SA_INIT describes the IKE SA
    # only); the IKE SA itself is still parsed from handshake bytes.
    assert body["fields"]["enc_alg"]["value"] == "aes-128-cbc"
    assert body["fields"]["enc_alg"]["source"] == "model"
    assert body["fields"]["enc_alg"]["status"] == "INFERRED"
    assert body["ike_sa"]["enc_alg"]["value"] == "aes-128-cbc"
    assert body["ike_sa"]["enc_alg"]["status"] == "OBSERVED"
    assert body["child_sa"]["proto"]["value"] == "esp"
    assert body["detection"]["ipsec_detected"] is True
    assert body["fields"]["traffic_type"]["source"] == "model"
    assert 0.0 <= body["ai_confidence"] <= 1.0
    # Live v1: posture 89 over evaluated controls, coverage 0.65
    # (dh/lifetime/replay unobserved in a short capture).
    assert body["assessment"]["posture_score"] == 89
    assert body["assessment"]["coverage"] == 0.65
    assert body["assessment"]["score_status"] == "PUBLISHED"
    ctl = {c["id"]: c for c in body["assessment"]["controls"]}
    assert ctl["lifetime"]["status"] == "UNKNOWN"
    assert ctl["replay"]["status"] == "UNKNOWN"
    assert ctl["lifetime"]["resolve_by"]
    assert not [f for f in body["assessment"]["findings"]
                if f["id"].startswith("unknown-")]


def test_report_and_rejects(tmp_path):
    data = _upload_copy(tmp_path)
    r = client.post("/report", files={"file": ("voip.pcap", data)})
    assert r.status_code == 200
    assert "assessment" in r.json()
    r = client.post("/analyze", files={"file": ("x.txt", b"not a pcap")})
    assert r.status_code == 400


def test_variants_and_samples():
    r = client.get("/variants")
    assert r.status_code == 200
    body = r.json()
    assert len(body["variants"]) == 20
    assert "plain" in body
    r = client.get("/datasets/samples?limit=10")
    assert r.status_code == 200
    body = r.json()
    assert len(body["samples"]) == 10
    # full corpus: 462 rows (396 synthetic incl. plain + 66 real);
    # clean checkouts that only regenerate synthetic data have 396.
    assert body["total_rows"] >= 396


def test_cors_preflight():
    r = client.options("/analyze", headers={
        "Origin": "http://localhost:3000",
        "Access-Control-Request-Method": "POST"})
    assert r.status_code == 200
    assert "http://localhost:3000" in r.headers.get("access-control-allow-origin", "")


def test_oversize_rejected():
    from engine.api import app as appmod
    assert appmod.MAX_BYTES == 50 * 1024 * 1024
    big = b"\xd4\xc3\xb2\xa1" + b"\x00" * (51 * 1024 * 1024)
    r = client.post("/analyze", files={"file": ("big.pcap", big)})
    assert r.status_code == 413


def test_mock_app():
    sys.path.insert(0, str(ROOT / "engine" / "api"))
    from mock import app as mock_app
    from fastapi.testclient import TestClient as TC
    mc = TC(mock_app)
    assert mc.get("/health").json()["mock"] is True
    r = mc.post("/analyze", files={"file": ("x.pcap", b"data")})
    assert r.status_code == 200
    body = r.json()
    assert body["fields"]["pfs"]["value"] == "unknown"
    assert body["fields"]["pfs"]["source"] == "model"
    assert body["fields"]["mode"]["detail"]["decided_by"] == \
        "size-overhead-model"
    assert body["ike_sa"]["version"]["value"] == "ikev2"
    assert body["child_sa"]["proto"]["value"] == "esp"
    assert body["detection"]["ipsec_detected"] is True
    assert mc.get("/variants").status_code == 200
    assert mc.get("/datasets/samples").status_code == 200


def test_cors_vite_origins():
    """Vite dev (:5173) + preview (:4173) origins allowed (config-only)."""
    from app import DEV_ORIGINS
    for origin in ("http://localhost:5173", "http://127.0.0.1:5173",
                   "http://localhost:4173", "http://127.0.0.1:4173"):
        assert origin in DEV_ORIGINS, origin
        r = client.options(
            "/analyze",
            headers={"Origin": origin,
                     "Access-Control-Request-Method": "POST"})
        assert r.status_code == 200, origin
        assert r.headers.get("access-control-allow-origin") == origin, origin
