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


def _f(value, source="parsed", confidence=1.0, detail=None):
    return {"value": value, "source": source, "confidence": confidence,
            "detail": detail}


SAMPLE = {
    "fields": {
        "ipsec_proto": _f("esp"),
        "ike_version": _f("ikev2"),
        "mode": _f("tunnel", "model", 0.99, {
            "header_parse": "n/a",
            "reason": "ESP payload encrypted: inner IP header and "
                      "next-header are not visible on the wire",
            "size_signal": {"value": "tunnel", "confidence": 0.99},
            "decided_by": "size-overhead-model"}),
        "enc_alg": _f("aes-128-cbc"),
        "enc_key_len": _f(128),
        "auth_alg": _f("hmac-sha256"),
        "dh_group": _f(14),
        "pfs": _f("unknown", "model", 0.0),
        "ip_version": _f(4),
        "traffic_type": _f("voip", "model", 0.97),
        "nat_t": _f(False),
    },
    "ai_confidence": 0.91,
    "metadata": {
        "duration_s": _f(8.34, "measured"),
        "n_packets": _f(407, "measured"),
        "packet_rate": _f(48.8, "measured"),
        "mean_bytes": _f(251.3, "measured"),
        "direction_ratio": _f(0.99, "measured"),
    },
    "assessment": {
        "security_score": 73,
        "risk_score": 27,
        "risk_level": "medium",
        "findings": [{"id": "unknown-lifetime", "severity": "medium",
                      "likelihood": 2, "impact": 3,
                      "text": "SA lifetime unknown: assuming weak.",
                      "solution": "Provide rekey intervals for scoring."}],
        "threat_matrix": [{"id": "unknown-lifetime", "likelihood": 2,
                           "impact": 3, "risk": 6}],
        "breakdown": {"cipher": 20, "dh": 15, "integrity": 13, "pfs": 10,
                      "lifetime": 0, "replay": 0, "ike": 10, "mode": 5},
    },
}


class FieldResult(BaseModel):
    value: object
    source: str
    confidence: float
    detail: dict[str, object] | None = None


class AnalyzeResponse(BaseModel):
    fields: dict[str, FieldResult]
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
