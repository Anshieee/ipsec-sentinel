"""CLI tests: every command incl. friendly errors (M4 req 2)."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "cli"))
from typer.testing import CliRunner  # noqa: E402
from main import app  # noqa: E402

runner = CliRunner()
SAMPLE = ROOT / "data" / "pcaps" / "synth" / "v1" / "r1" / "voip.pcap"


def _copy_sample(tmp_path, src=SAMPLE):
    """Isolated working copy: tests must never write into data/."""
    import shutil
    dest = tmp_path / src.name
    shutil.copy(src, dest)
    return dest


def test_analyze_human_and_json(tmp_path):
    sample = _copy_sample(tmp_path)
    r = runner.invoke(app, ["analyze", str(sample)])
    assert r.exit_code == 0, r.output
    assert "aes-128-cbc" in r.output
    assert "parsed" in r.output
    r = runner.invoke(app, ["analyze", str(sample), "--json"])
    assert r.exit_code == 0
    body = json.loads(r.output)
    assert body["fields"]["dh_group"]["value"] == 14
    assert body["fields"]["mode"]["detail"]["decided_by"] == \
        "size-overhead-model"


def test_analyze_report_pdf(tmp_path):
    sample = _copy_sample(tmp_path)
    r = runner.invoke(app, ["analyze", str(sample), "--report", "pdf"])
    assert r.exit_code == 0, r.output
    pdf = sample.parent / (sample.stem + ".report.pdf")
    assert pdf.exists() and pdf.stat().st_size > 1000
    # tmp_path auto-cleans; nothing may remain in data/


def test_report_pdf_missing_backend(tmp_path, monkeypatch):
    """Without reportlab: one-line error naming package + install cmd."""
    import sys
    sample = _copy_sample(tmp_path)
    monkeypatch.setitem(sys.modules, "reportlab", None)
    for mod in [m for m in list(sys.modules)
                if m == "build" or m.startswith("build.")]:
        monkeypatch.delitem(sys.modules, mod, raising=False)
    r = runner.invoke(app, ["analyze", str(sample), "--report", "pdf"])
    assert r.exit_code == 3, r.output
    assert "reportlab" in r.output and "pip install" in r.output
    assert "Traceback" not in r.output


def test_analyze_errors(tmp_path):
    r = runner.invoke(app, ["analyze", str(tmp_path / "nope.pcap")])
    assert r.exit_code == 2 and "no such file" in r.output
    bad = tmp_path / "x.txt"
    bad.write_text("hello")
    r = runner.invoke(app, ["analyze", str(bad)])
    assert r.exit_code == 2 and ".pcap" in r.output
    upper = tmp_path / "U.PCAP"
    upper.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 24)
    r = runner.invoke(app, ["analyze", str(upper)])
    assert r.exit_code in (0, 1)  # suffix casefolded: parsed or clean fail
    empty = tmp_path / "e.pcap"
    empty.write_bytes(b"")
    r = runner.invoke(app, ["analyze", str(empty)])
    assert r.exit_code == 2 and "empty" in r.output
    corrupt = tmp_path / "c.pcap"
    corrupt.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)
    r = runner.invoke(app, ["analyze", str(corrupt)])
    assert r.exit_code in (0, 1), r.output  # parses as empty pcap or fails cleanly


def test_batch(tmp_path):
    batchdir = tmp_path / "batch"
    batchdir.mkdir()
    for src in (SAMPLE.parent).glob("*.pcap"):
        import shutil
        shutil.copy(src, batchdir / src.name)
    r = runner.invoke(app, ["batch", str(batchdir), "--json"])
    assert r.exit_code == 0, r.output
    rows = json.loads(r.output)
    assert isinstance(rows, list) and len(rows) >= 1
    (tmp_path / "empty").mkdir()
    r = runner.invoke(app, ["batch", str(tmp_path / "empty")])
    assert r.exit_code == 2 and "no .pcap" in r.output


def test_train_evaluate_generate_help():
    for cmd in (["train", "--help"], ["evaluate", "--help"],
                ["generate-data", "--help"], ["serve", "--help"],
                ["batch", "--help"]):
        r = runner.invoke(app, cmd)
        assert r.exit_code == 0, cmd
    r = runner.invoke(app, ["serve", "--help"])
    assert "--mock" in r.output
