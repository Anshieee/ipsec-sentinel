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
    assert body["fields"]["enc_alg"]["value"] == "aes-128-cbc"
    assert body["fields"]["enc_alg"]["source"] == "parsed"
    assert body["fields"]["traffic_type"]["source"] == "model"
    assert 0.0 <= body["ai_confidence"] <= 1.0
    # 88 (label-oracle) minus lifetime(10) and replay(5): an 8 s capture
    # cannot observe rekey intervals, so the API scores them unknown.
    assert body["assessment"]["security_score"] == 73
    ids = {f["id"] for f in body["assessment"]["findings"]}
    assert "unknown-lifetime" in ids and "unknown-replay" in ids


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
    assert len(body["variants"]) == 18
    assert "plain" in body
    r = client.get("/datasets/samples?limit=10")
    assert r.status_code == 200
    body = r.json()
    assert len(body["samples"]) == 10
    # full corpus: 402 (360 synthetic + 42 real); clean checkouts that
    # only regenerate synthetic data have 360.
    assert body["total_rows"] >= 360


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
    assert body["fields"]["pfs"] == {"value": "unknown", "source": "model",
                                     "confidence": 0.0, "detail": None}
    assert body["fields"]["mode"]["detail"]["decided_by"] == \
        "size-overhead-model"
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
