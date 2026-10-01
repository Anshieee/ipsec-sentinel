#!/usr/bin/env python3
"""ipsec-analyze CLI (M4, Typer): analyze, batch, train, evaluate,
generate-data, serve. Friendly errors for empty/corrupt/non-pcap input.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import typer

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine" / "classifier"))
sys.path.insert(0, str(ROOT / "engine" / "assess"))
from predict import analyze as analyze_pcap  # noqa: E402
from assess import assess  # noqa: E402

app = typer.Typer(name="ipsec-analyze", no_args_is_help=True)
MODELS_DIR = ROOT / "engine" / "models"


def _need_models():
    if not (MODELS_DIR / "vectorizer.joblib").exists():
        typer.echo("models missing: run `ipsec-analyze train` first.",
                   err=True)
        raise typer.Exit(2)


def _analyze_path(pcap: Path) -> dict:
    if not pcap.exists():
        typer.echo(f"error: no such file: {pcap}", err=True)
        raise typer.Exit(2)
    if pcap.suffix.lower() != ".pcap":
        typer.echo(f"error: not a .pcap file: {pcap}", err=True)
        raise typer.Exit(2)
    if pcap.stat().st_size == 0:
        typer.echo(f"error: empty file: {pcap}", err=True)
        raise typer.Exit(2)
    _need_models()
    try:
        out = analyze_pcap(str(pcap), MODELS_DIR)
    except Exception as e:
        typer.echo(f"error: corrupt or unreadable pcap {pcap}: {e}", err=True)
        raise typer.Exit(1)
    sys.path.insert(0, str(ROOT / "engine" / "api"))
    from app import to_response
    return to_response(out)


def _print_human(name: str, resp: dict):
    typer.echo(f"== {name} (AI confidence {resp['ai_confidence']:.2f})")
    for k, v in resp["fields"].items():
        det = f" [{v['detail']['decided_by']}]" if v.get("detail") else ""
        typer.echo(f"  {k:13s} {str(v['value']):16s} {v['source']:7s} "
                   f"{v['confidence']:.2f}{det}")
    a = resp["assessment"]
    typer.echo(f"  security {a['security_score']}/100 risk {a['risk_score']} "
               f"({a['risk_level']})")
    for f in a["findings"][:5]:
        typer.echo(f"  [{f['severity']}] {f['text']}")


@app.command()
def analyze(pcap: Path, json_out: bool = typer.Option(
        False, "--json", help="machine-readable JSON"),
        report: str = typer.Option(
        "", "--report", help="write PDF report (pdf)")):
    """Analyze one pcap."""
    out = _analyze_path(pcap)
    if report == "pdf":
        try:
            import reportlab  # noqa: F401 (backend presence probe)
        except ImportError:
            typer.echo("error: PDF reports need 'reportlab': "
                       "pip install -r requirements.txt", err=True)
            raise typer.Exit(3)
        sys.path.insert(0, str(ROOT / "reports"))
        from build import technical
        dest = pcap.with_suffix(".report.pdf")
        technical(out, dest, pcap.name)
        typer.echo(f"report -> {dest}")
    elif report:
        typer.echo("error: --report only supports 'pdf'", err=True)
        raise typer.Exit(2)
    if json_out:
        typer.echo(json.dumps(out, indent=1, default=str))
    else:
        _print_human(str(pcap), out)


@app.command()
def batch(directory: Path, json_out: bool = typer.Option(
        False, "--json", help="machine-readable JSON")):
    """Analyze every .pcap in a directory."""
    if not directory.is_dir():
        typer.echo(f"error: no such directory: {directory}", err=True)
        raise typer.Exit(2)
    files = sorted(directory.rglob("*.pcap"))
    if not files:
        typer.echo(f"error: no .pcap files under {directory}", err=True)
        raise typer.Exit(2)
    results = []
    for f in files:
        try:
            out = _analyze_path(f)
        except typer.Exit as e:
            results.append({"file": str(f), "error": f"exit {e.exit_code}"})
            continue
        results.append({"file": str(f), **out})
    if json_out:
        typer.echo(json.dumps(results, indent=1, default=str))
    else:
        for r in results:
            if "error" in r:
                typer.echo(f"== {r['file']}: {r['error']}")
            else:
                _print_human(r["file"], r)


@app.command()
def train():
    """Train per-field classifiers (deterministic, seed 7)."""
    sys.path.insert(0, str(ROOT / "engine" / "classifier"))
    from train import main as train_main
    sys.argv = ["train"]
    raise typer.Exit(train_main())


@app.command()
def evaluate():
    """Grouped eval + ablation + synth->real (writes docs/)."""
    sys.path.insert(0, str(ROOT / "engine" / "eval"))
    from evaluate import main as eval_main
    sys.argv = ["evaluate"]
    raise typer.Exit(eval_main())


@app.command(name="generate-data")
def generate_data(real: bool = typer.Option(
        False, "--real", help="also fold data/real labels + manifest")):
    """Regenerate synthetic pcaps + labels + manifest (deterministic)."""
    import subprocess
    r = subprocess.run([sys.executable, "capture/synth/synth_pcap.py"],
                       cwd=str(ROOT))
    if r.returncode != 0:
        raise typer.Exit(r.returncode)
    if real:
        r = subprocess.run(
            [sys.executable, "capture/synth/synth_pcap.py", "--ingest-real"],
            cwd=str(ROOT))
        if r.returncode != 0:
            raise typer.Exit(r.returncode)


@app.command()
def serve(mock: bool = typer.Option(
        False, "--mock", help="deterministic sample responses, no model"),
        port: int = typer.Option(8000, "--port")):
    """Serve the API (real or --mock for frontend development)."""
    import uvicorn
    # import the app object (not a "module:attr" string: uvicorn's
    # importer cannot resolve our packages from an installed entry point
    # in an arbitrary cwd).
    sys.path.insert(0, str(ROOT))
    if mock:
        from engine.api.mock import app as mock_app
        typer.echo(f"mock API on :{port} (deterministic samples)")
        uvicorn.run(mock_app, host="127.0.0.1", port=port)
    else:
        from engine.api.app import app as real_app
        uvicorn.run(real_app, host="127.0.0.1", port=port)


if __name__ == "__main__":
    app()
