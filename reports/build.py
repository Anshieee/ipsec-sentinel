"""PDF reports (M4): executive, technical, comparative (reportlab).

Every report shows per-field confidence, `unknown` fields, and the
synthetic-vs-real caveat. No dashboard dependency.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CAVEAT = ("Caveat: synthetic pcaps prove pipeline behavior on the synthetic "
          "distribution only; the 42+ real captures (v1,v3,v5,v7,v12,v18) "
          "are the only out-of-distribution evidence. Lifetimes, replay "
          "state and ESN are never observed in short captures.")


def _doc(path: Path, title: str):
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import BaseDocTemplate, PageTemplate, Frame, \
        Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    doc = BaseDocTemplate(str(path), pagesize=A4,
                          leftMargin=40, rightMargin=40)
    frame = Frame(40, 40, A4[0] - 80, A4[1] - 80, id="f")
    doc.addPageTemplates([PageTemplate(id="p", frames=[frame])])
    styles = getSampleStyleSheet()
    return doc, styles


def _field_table(analysis: dict, styles) -> list:
    from reportlab.platypus import Table, TableStyle, Paragraph
    from reportlab.lib import colors
    rows = [[Paragraph(f"<b>{k}</b>", styles["Normal"]),
             Paragraph(str(v["value"]), styles["Normal"]),
             Paragraph(v["source"], styles["Normal"]),
             Paragraph(f"{v['confidence']:.2f}", styles["Normal"])]
            for k, v in analysis["fields"].items()]
    head = [Paragraph(f"<b>{h}</b>", styles["Normal"]) for h in
            ("field", "value", "source", "conf")]
    t = Table([head] + rows, colWidths=[110, 170, 80, 60])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                           ("BACKGROUND", (0, 0), (-1, 0),
                            colors.lightgrey)]))
    return [t]


def executive(analysis: dict, out: Path):
    """1-page executive summary."""
    from reportlab.platypus import Paragraph, Spacer
    doc, styles = _doc(out, "Executive")
    a = analysis["assessment"]
    story = [Paragraph("IPsec Assessment — Executive Summary", styles["Title"]),
             Spacer(1, 12),
             Paragraph(f"Security score <b>{a['security_score']}/100</b> "
                       f"(risk {a['risk_score']}, level {a['risk_level']}); "
                       f"AI confidence {analysis['ai_confidence']:.2f}.",
                       styles["Normal"]),
             Spacer(1, 12)]
    story += _field_table(analysis, styles)
    story += [Spacer(1, 12)]
    for f in a["findings"][:5]:
        story.append(Paragraph(
            f"<b>[{f['severity']}]</b> {f['text']} — {f['solution']}",
            styles["Normal"]))
    story += [Spacer(1, 12), Paragraph(CAVEAT, styles["Normal"])]
    doc.build(story)


def technical(analysis: dict, out: Path, pcap_name: str = ""):
    """Full technical report: fields, breakdown, threats, metadata."""
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    doc, styles = _doc(out, "Technical")
    a = analysis["assessment"]
    story = [Paragraph(f"IPsec Technical Report {pcap_name}", styles["Title"]),
             Spacer(1, 12),
             Paragraph(f"Security <b>{a['security_score']}</b> / Risk "
                       f"<b>{a['risk_score']} ({a['risk_level']})</b> / AI "
                       f"confidence {analysis['ai_confidence']:.2f}.",
                       styles["Normal"]),
             Spacer(1, 8),
             Paragraph("Classification (unknown = system declined):",
                       styles["Heading3"])]
    story += _field_table(analysis, styles)
    story += [Spacer(1, 8),
              Paragraph("Score breakdown:", styles["Heading3"]),
              Paragraph(str(a["breakdown"]), styles["Normal"]),
              Spacer(1, 8),
              Paragraph("Threat matrix (likelihood x impact):",
                        styles["Heading3"])]
    trows = [[Paragraph(f"<b>{t['id']}</b>", styles["Normal"]),
              str(t["likelihood"]), str(t["impact"]), str(t["risk"])]
             for t in a["threat_matrix"]]
    if trows:
        t = Table([[Paragraph(f"<b>{h}</b>", styles["Normal"]) for h in
                    ("threat", "L", "I", "R")]] + trows,
                  colWidths=[220, 40, 40, 40])
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.grey)]))
        story.append(t)
    story += [Spacer(1, 8),
              Paragraph("Findings + remediation:", styles["Heading3"])]
    for f in a["findings"]:
        story.append(Paragraph(
            f"<b>[{f['severity']}] {f['id']}</b>: {f['text']}<br/>"
            f"Solution: {f['solution']}", styles["Normal"]))
    story += [Spacer(1, 8),
              Paragraph("Observed metadata:", styles["Heading3"])]
    for k, v in analysis.get("metadata", {}).items():
        story.append(Paragraph(f"{k}: {v['value']} ({v['source']})",
                               styles["Normal"]))
    story += [Spacer(1, 12), Paragraph(CAVEAT, styles["Normal"])]
    doc.build(story)


def comparative(rows: list[dict], out: Path):
    """One row per variant: scores + key fields (all 18 + plain)."""
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    doc, styles = _doc(out, "Comparative")
    story = [Paragraph("IPsec Variants — Comparative Report", styles["Title"]),
             Spacer(1, 12)]
    head = [Paragraph(f"<b>{h}</b>", styles["Normal"]) for h in
            ("variant", "score", "risk", "cipher", "dh", "mode", "conf")]
    body = []
    for r in rows:
        f = r["analysis"]["fields"]
        a = r["analysis"]["assessment"]
        body.append([r["variant"], a["security_score"], a["risk_level"],
                     str(f["enc_alg"]["value"]), str(f["dh_group"]["value"]),
                     str(f["mode"]["value"]),
                     f"{r['analysis']['ai_confidence']:.2f}"])
    t = Table([head] + [[Paragraph(str(c), styles["Normal"]) for c in row]
                        for row in body],
              colWidths=[60, 45, 60, 90, 40, 70, 45])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                           ("BACKGROUND", (0, 0), (-1, 0),
                            colors.lightgrey)]))
    story += [t, Spacer(1, 12), Paragraph(CAVEAT, styles["Normal"])]
    doc.build(story)
