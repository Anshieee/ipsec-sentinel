"""Deterministic mock API for frontend development (M4).

Same routes/schemas as engine.api.app, fixed sample payloads, no model.
Run: ipsec-analyze serve --mock
"""
from __future__ import annotations

from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="IPsec Analyzer (mock)", version="0.3.0-mock")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000",
                   "http://localhost:8501", "http://127.0.0.1:8501",
                   "http://localhost:8000", "http://127.0.0.1:8000"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def _f(value, source="parsed", confidence=1.0, detail=None,
       status="OBSERVED"):
    return {"value": value, "source": source, "confidence": confidence,
            "status": status, "detail": detail, "evidence": None}


SAMPLE = {
    "fields": {
        "ipsec_proto": _f("esp"),
        "ike_version": _f("ikev2"),
        "mode": _f("tunnel", "model", 0.99, {
            "header_parse": "n/a",
            "reason": "ESP payload encrypted: inner IP header and "
                      "next-header are not visible on the wire",
            "size_signal": {"value": "tunnel", "confidence": 0.99},
            "decided_by": "size-overhead-model"}, "INFERRED"),
        "enc_alg": _f("aes-128-cbc", "model", 0.93, None, "INFERRED"),
        "enc_key_len": _f(128, "model", 0.93, None, "INFERRED"),
        "auth_alg": _f("hmac-sha256", "model", 0.94, None, "INFERRED"),
        "dh_group": _f("unknown", "none", 0.0, None, "NOT_OBSERVED"),
        "pfs": _f(True, "model", 1.0, None, "INFERRED"),
        "ip_version": _f(4),
        "traffic_type": _f("voip", "model", 0.97, None, "INFERRED"),
        "nat_t": _f(False),
    },
    "ike_sa": {
        "version": _f("ikev2"),
        "enc_alg": _f("aes-128-cbc"),
        "enc_key_len": _f(128),
        "auth_alg": _f("hmac-sha256"),
        "prf": _f("hmac-sha256"),
        "dh_group": _f(14),
    },
    "child_sa": {
        "proto": _f("esp"),
        "mode": _f("tunnel", "model", 0.99, None, "INFERRED"),
        "enc_alg": _f("aes-128-cbc", "model", 0.93, None, "INFERRED"),
        "enc_key_len": _f(128, "model", 0.93, None, "INFERRED"),
        "auth_alg": _f("hmac-sha256", "model", 0.94, None, "INFERRED"),
        "pfs": _f(True, "model", 1.0, None, "INFERRED"),
        "replay": _f("unknown", "none", 0.0, None, "NOT_OBSERVED"),
        "lifetime": _f("unknown", "none", 0.0, None, "NOT_OBSERVED"),
    },
    "detection": {"ipsec_detected": True, "source": "measured",
                  "confidence": 1.0,
                  "evidence": {"n_packets": 407, "n_esp": 399, "n_ah": 0,
                               "n_ike": 6}},
    "ai_confidence": 0.91,
    "metadata": {
        "duration_s": _f(8.34, "measured"),
        "n_packets": _f(407, "measured"),
        "packet_rate": _f(48.8, "measured"),
        "mean_bytes": _f(251.3, "measured"),
        "direction_ratio": _f(0.99, "measured"),
    },
    "assessment": {
        "posture_score": 89,
        "coverage": 0.6509,
        "score_status": "PUBLISHED",
        "security_score": 89,
        "risk_score": 11,
        "risk_level": "low",
        "rule_version": "1.2.0",
        "controls": [],
        "findings": [],
        "threat_matrix": [],
        "breakdown": {"cipher": 20, "dh": 0, "integrity": 13, "pfs": 10,
                      "lifetime": 0, "replay": 0, "ike": 10,
                      "ike_cipher": 4, "ike_integrity": 3, "mode": 5},
    },
}


class FieldResult(BaseModel):
    value: object
    source: str
    confidence: float
    status: str = "OBSERVED"
    detail: dict[str, object] | None = None
    evidence: dict[str, object] | None = None


class AnalyzeResponse(BaseModel):
    fields: dict[str, FieldResult]
    ike_sa: dict[str, FieldResult]
    child_sa: dict[str, FieldResult]
    detection: dict
    ai_confidence: float
    metadata: dict[str, FieldResult]
    assessment: dict


@app.get("/health")
def health():
    return {"status": "ok", "models_loaded": False, "mock": True}


@app.get("/models")
def models():
    return {"fields": ["traffic_type", "mode", "enc_alg", "enc_key_len",
                       "auth_alg", "dh_group"],
            "classes": {"traffic_type": ["email", "icmp", "video", "voip",
                                         "web", "whatsapp"]},
            "meta": {"seed": 7, "mock": True}}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_pcap(file: UploadFile = File(...)):
    return SAMPLE


@app.post("/report", response_model=AnalyzeResponse)
async def report_pcap(file: UploadFile = File(...)):
    return SAMPLE


@app.get("/variants")
def list_variants():
    return {"variants": [{"variant": "v1", "mode": "tunnel"}],
            "mock": True}


@app.get("/datasets/samples")
def dataset_samples(limit: int = 12):
    return {"samples": [], "total_rows": 0, "mock": True}
