"""FastAPI service (M3): analyze pcaps, serve models metadata, reports.

Endpoints: POST /analyze, GET /health, GET /models, POST /report.
Safe uploads: .pcap suffix, 50 MB cap, temp file removed after analysis.
Mock mode + frozen contract + CORS arrive in M4 (frontend scope).
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engine" / "classifier"))
sys.path.insert(0, str(ROOT / "engine" / "assess"))
from predict import analyze, SCORED  # noqa: E402
from assess import assess  # noqa: E402

from fastapi import FastAPI, File, UploadFile, HTTPException  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from pydantic import BaseModel  # noqa: E402

MODELS_DIR = ROOT / "engine" / "models"
MAX_BYTES = 50 * 1024 * 1024

DEV_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000",
                 "http://localhost:8501", "http://127.0.0.1:8501",
                 "http://localhost:8000", "http://127.0.0.1:8000",
                 "http://localhost:5173", "http://127.0.0.1:5173",
                 "http://localhost:4173", "http://127.0.0.1:4173"]

app = FastAPI(title="IPsec Analyzer", version="0.3.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=DEV_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


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


def _wire(obj: dict) -> dict:
    return {"value": obj["value"], "source": obj["source"],
            "confidence": obj["confidence"],
            "status": obj.get("status", "OBSERVED"),
            "detail": obj.get("detail"),
            "evidence": obj.get("evidence")}


def to_response(out: dict) -> dict:
    """API-shaped dict from analyze() output (shared with the CLI)."""
    fields = {k: _wire(v) for k, v in out.items() if k in SCORED}
    ike_sa = {k: _wire(v) for k, v in out.get("ike_sa", {}).items()}
    child_sa = {k: _wire(v) for k, v in out.get("child_sa", {}).items()}
    metadata = {k: {"value": v["value"], "source": v["source"],
                    "confidence": v["confidence"],
                    "status": v.get("status", "OBSERVED")}
                for k, v in out.get("metadata", {}).items()}
    return {"fields": fields, "ike_sa": ike_sa, "child_sa": child_sa,
            "detection": out.get("detection", {}),
            "ai_confidence": out["ai_confidence"],
            "metadata": metadata, "assessment": assess(out)}


async def _read_capped(file: UploadFile) -> bytes:
    """Read at most MAX_BYTES+1 (bound memory/disk before size check)."""
    chunks, total = [], 0
    while True:
        blob = await file.read(1024 * 1024)
        if not blob:
            break
        total += len(blob)
        if total > MAX_BYTES:
            raise HTTPException(413, "pcap too large")
        chunks.append(blob)
    return b"".join(chunks)


def _analyze_bytes(data: bytes, filename: str) -> AnalyzeResponse:
    if not filename.lower().endswith(".pcap"):
        raise HTTPException(400, "only .pcap uploads accepted")
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        out = analyze(tmp_path, MODELS_DIR)
    except Exception as e:
        raise HTTPException(422, f"analysis failed: {e}")
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    return AnalyzeResponse(**to_response(out))


@app.get("/health")
def health():
    return {"status": "ok",
            "models_loaded": (MODELS_DIR / "vectorizer.joblib").exists()}


@app.get("/models")
def models():
    import json
    meta = json.loads((MODELS_DIR / "meta.json").read_text())
    classes = json.loads((MODELS_DIR / "classes.json").read_text())
    return {"fields": sorted(classes), "classes": classes, "meta": meta}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_pcap(file: UploadFile = File(...)):
    data = await _read_capped(file)
    return _analyze_bytes(data, file.filename or "")


@app.post("/report", response_model=AnalyzeResponse)
async def report_pcap(file: UploadFile = File(...)):
    """Full JSON report (classification + assessment + remediation).

    PDF rendering arrives in M4; the payload here is the report content.
    """
    return await analyze_pcap(file)


@app.get("/variants")
def list_variants():
    """Demo data: the 18-variant matrix + plain (ground truth table)."""
    sys.path.insert(0, str(ROOT / "testbed"))
    import matrix
    return {"variants": [matrix.label_row(v) for v in matrix.VARIANTS],
            "plain": {"variant": "plain", "ipsec_protocol": "none",
                      "ike_version": "none", "mode": "none",
                      "encryption": "none", "key_length_bits": 0,
                      "auth": "none", "aead": False, "dh_group": 0,
                      "pfs": False, "esn": False, "replay_window": 0,
                      "nat_t": False, "ike_rekey_s": 0, "child_rekey_s": 0}}


@app.get("/datasets/samples")
def dataset_samples(limit: int = 12):
    """Demo data: sample manifest rows (small, stable selection)."""
    import csv
    rows = list(csv.DictReader(
        (ROOT / "data" / "manifest.csv").open()))
    synth = [r for r in rows if r["source"] == "synthetic"]
    real = [r for r in rows if r["source"] == "real"]
    half = limit // 2
    out = real[:half] + synth[:limit - min(len(real), half)]
    return {"samples": out, "total_rows": len(rows)}
