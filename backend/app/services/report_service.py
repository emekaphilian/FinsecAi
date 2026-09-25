"""Incident PDF report generation."""

from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.db.models import Incident

OUTPUT_DIR = Path(__file__).resolve().parents[2] / "tmp" / "finsecai_reports"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

PAGE_W, PAGE_H = letter

# ---------------------------------------------------------------- Palette --
GOLD = colors.HexColor("#B8860B")
DARK = colors.HexColor("#0F172A")
GRAY = colors.HexColor("#475569")
LIGHT_GRAY = colors.HexColor("#94A3B8")
RED = colors.HexColor("#B91C1C")
AMBER = colors.HexColor("#B45309")
GREEN = colors.HexColor("#15803D")
LIGHT_GRID = colors.HexColor("#E2E8F0")
PANEL_BG = colors.HexColor("#F8FAFC")
WARN_BG = colors.HexColor("#FEF3C7")
WHITE = colors.white

RISK_BADGE_COLORS = {
    "critical_risk_transaction": RED,
    "high_risk_transaction": RED,
    "elevated_risk_transaction": AMBER,
    "moderate_risk_transaction": AMBER,
    "low_risk_transaction": GREEN,
}
DEFAULT_BADGE_COLOR = LIGHT_GRAY

MISSING = "Not available in supplied incident data"

# ----------------------------------------------------------------- Styles --
_styles = getSampleStyleSheet()
_styles.add(ParagraphStyle(
    "ReportTitle", parent=_styles["Title"], textColor=DARK, fontSize=19,
    leading=22, spaceAfter=2, alignment=0,
))
_styles.add(ParagraphStyle(
    "ReportKicker", parent=_styles["Normal"], textColor=GOLD, fontSize=9,
    fontName="Helvetica-Bold", spaceAfter=4,
))
_styles.add(ParagraphStyle("Meta", parent=_styles["Normal"], textColor=GRAY, fontSize=9))
_styles.add(ParagraphStyle(
    "SectionHeading", parent=_styles["Heading2"], textColor=DARK, fontSize=12.5,
    spaceBefore=16, spaceAfter=6, fontName="Helvetica-Bold",
))
_styles.add(ParagraphStyle(
    "Body", parent=_styles["Normal"], fontSize=10, leading=15,
))
_styles.add(ParagraphStyle(
    "BodyMuted", parent=_styles["Normal"], fontSize=9.5, leading=14,
    textColor=GRAY, fontName="Helvetica-Oblique",
))
_styles.add(ParagraphStyle("FlagText", parent=_styles["Normal"], fontSize=10, textColor=RED))
_styles.add(ParagraphStyle(
    "Notice", parent=_styles["Normal"], fontSize=10, leading=14,
    textColor=DARK, backColor=WARN_BG, borderColor=GOLD,
    borderWidth=0.5, borderPadding=8,
))
_styles.add(ParagraphStyle(
    "BadgeText", parent=_styles["Normal"], fontSize=9.5, textColor=WHITE,
    fontName="Helvetica-Bold", alignment=1, leading=12,
))


class ReportGenerationError(ValueError):
    """A full report cannot exist without persisted investigation analysis."""


# ------------------------------------------------------------ Small utils --
def _display(value: Any) -> str:
    return escape(str(value)) if value not in (None, "") else MISSING


def _paragraph(value: Any, style: str = "Body") -> Paragraph:
    return Paragraph(_display(value), _styles[style])


def _section(story: list, number: int, title: str) -> None:
    story.append(Paragraph(
        f'<font color="#B8860B">{number:02d}</font> &nbsp; {escape(title)}',
        _styles["SectionHeading"],
    ))
    story.append(HRFlowable(width="100%", thickness=0.75, color=LIGHT_GRID, spaceAfter=6))


def _table(rows: list[list[Any]], widths: list[float], header: bool = True) -> Table:
    content = [
        [cell if isinstance(cell, Paragraph) else _paragraph(cell, "Meta") for cell in row]
        for row in rows
    ]
    table = Table(content, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, LIGHT_GRID),
    ]
    if header:
        style.extend((
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BACKGROUND", (0, 0), (-1, 0), DARK),
            ("BACKGROUND", (0, 1), (-1, -1), PANEL_BG),
        ))
    else:
        # Zebra-stripe key/value tables for readability.
        for row_index in range(len(content)):
            if row_index % 2 == 1:
                style.append(("BACKGROUND", (0, row_index), (-1, row_index), PANEL_BG))
    table.setStyle(TableStyle(style))
    return table


def _badge(text: str, color: colors.Color) -> Table:
    """Small pill-style colored label, e.g. for risk classification."""
    tbl = Table([[Paragraph(escape(text.replace("_", " ").upper()), _styles["BadgeText"])]],
                colWidths=[2.3 * inch])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    return tbl


def _framework_rows(entries: list[dict[str, Any]], framework: str) -> list[list[Any]]:
    rows = [["Mapping", "Status", "Basis"]]
    for entry in entries:
        # The intelligence pipeline persists this provenance. A report must
        # never infer a confirmed mapping from a risk score or text itself.
        status = entry.get("status") or "candidate"
        basis = entry.get("basis") or "Persisted provenance unavailable"
        rows.append([
            f"{framework} {entry.get('id') or MISSING} — {entry.get('name') or MISSING}",
            "Evidence-backed" if status == "evidence_backed" else "Candidate",
            basis,
        ])
    return rows


def _first_value(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = payload.get(key)
        if value not in (None, ""):
            return value
    return None


# -------------------------------------------------------- Page chrome ------
class _NumberedCanvas(pdfcanvas.Canvas):
    """Canvas subclass that defers page-number drawing until the total page
    count is known, so the footer can read 'Page X of Y'."""

    def __init__(self, *args, **kwargs):
        pdfcanvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states: list[dict] = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_page_number(total_pages)
            pdfcanvas.Canvas.showPage(self)
        pdfcanvas.Canvas.save(self)

    def _draw_page_number(self, total_pages: int) -> None:
        self.setFont("Helvetica", 8)
        self.setFillColor(GRAY)
        self.drawRightString(PAGE_W - 0.7 * inch, 0.38 * inch, f"Page {self._pageNumber} of {total_pages}")


def _make_page_decorator(incident_short_id: str):
    """Returns an onPage callback that draws the top accent band, a running
    header on pages after the first, and the footer rule + confidentiality
    line. Page numbering itself is handled by _NumberedCanvas."""

    def _decorate(canvas, doc):
        canvas.saveState()

        # Top accent band.
        canvas.setFillColor(DARK)
        canvas.rect(0, PAGE_H - 0.14 * inch, PAGE_W, 0.14 * inch, fill=1, stroke=0)
        canvas.setFillColor(GOLD)
        canvas.rect(0, PAGE_H - 0.18 * inch, PAGE_W, 0.04 * inch, fill=1, stroke=0)

        # Running header on continuation pages.
        if doc.page > 1:
            canvas.setFont("Helvetica-Bold", 8)
            canvas.setFillColor(GRAY)
            canvas.drawString(0.7 * inch, PAGE_H - 0.42 * inch,
                               f"FinSecAI Investigation Report — Incident {incident_short_id}")
            canvas.setFont("Helvetica", 8)
            canvas.drawRightString(PAGE_W - 0.7 * inch, PAGE_H - 0.42 * inch, "CONFIDENTIAL")

        # Footer rule + confidentiality line (page number added by canvas).
        canvas.setStrokeColor(LIGHT_GRID)
        canvas.setLineWidth(0.6)
        canvas.line(0.7 * inch, 0.55 * inch, PAGE_W - 0.7 * inch, 0.55 * inch)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(GRAY)
        canvas.drawString(
            0.7 * inch, 0.38 * inch,
            "FinSecAI SOC Command Center · Confidential · Generated automatically, review before distribution",
        )

        canvas.restoreState()

    return _decorate


# ------------------------------------------------------------- Fallbacks ---
def _fallback_actions(incident: Incident) -> list[str]:
    actions = [
        f"Review the transaction history for {incident.user_id}.",
        "Retrieve supporting evidence records where available.",
        "Confirm whether the observed anomaly represents legitimate activity.",
        "Escalate for enhanced review if the anomalies remain unexplained.",
    ]
    if incident.device_id:
        actions.insert(1, f"Validate the device context involving {incident.device_id}.")
    if incident.governance_flags and "geo" in incident.governance_flags.lower():
        actions.insert(2, "Review the geographic context associated with the transaction.")
    return actions


def _fallback_reasoning(incident: Incident, analysis: dict[str, Any], evidence: list[dict[str, Any]]) -> list[str]:
    reasoning = list(analysis.get("risk_rationale") or [])
    if reasoning:
        return reasoning

    result = [
        f"The transaction received a risk score of {incident.risk_score:.2f}, placing it in the "
        f"{analysis.get('incident_classification') or 'elevated-risk'} tier.",
        f"The anomaly engine recorded an anomaly score of {incident.anomaly_score:.2f}.",
    ]
    if incident.device_id:
        result.append(
            f"Device context was recorded as {incident.device_id}; an underlying comparison record "
            "is not available in the supplied incident data."
        )
    if incident.governance_flags:
        result.append(f"Governance signals recorded for review: {incident.governance_flags}.")
    if not evidence:
        result.append(
            "No underlying evidence records were returned, so this assessment is based primarily on "
            "structured transaction and model signals."
        )
    return result


# --------------------------------------------------------------- Main -----
def generate_incident_pdf(incident: Incident) -> str:
    """Render persisted investigation data without recreating conclusions."""
    analysis = incident.analysis_json or {}
    if not analysis:
        raise ReportGenerationError(
            "Full investigation reports require persisted analysis_json. Run investigation analysis first."
        )

    path = OUTPUT_DIR / f"report_{incident.id}.pdf"
    incident_short_id = incident.id[:8]

    doc = SimpleDocTemplate(
        str(path), pagesize=letter,
        topMargin=0.85 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
        title=f"FinSecAI Investigation Report — {incident_short_id}",
    )

    assessment = analysis.get("risk_assessment") or {}
    governance = analysis.get("governance") or {}
    evidence = analysis.get("evidence") or []
    recommendations = analysis.get("recommendations") or analysis.get("next_actions") or []
    structured_evidence = analysis.get("structured_evidence") or []
    classification = analysis.get("incident_classification") or MISSING
    coverage = incident.evidence_coverage
    payload = incident.raw_payload or {}
    client_name = _first_value(
        payload, "user_full_name", "client_name", "customer_name", "full_name", "name"
    )
    badge_color = RISK_BADGE_COLORS.get(analysis.get("incident_classification") or "", DEFAULT_BADGE_COLOR)

    story: list = []

    # ---- Title block with risk badge -------------------------------------
    story.append(Paragraph("FINSECAI · SOC COMMAND CENTER", _styles["ReportKicker"]))
    title_row = Table(
        [[
            Paragraph("Investigation Report", _styles["ReportTitle"]),
            _badge(classification if classification != MISSING else "unclassified", badge_color),
        ]],
        colWidths=[4.4 * inch, 2.4 * inch],
    )
    title_row.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(title_row)
    story.append(Paragraph(
        f"Incident {escape(incident_short_id)} &nbsp;&middot;&nbsp; Generated "
        f"{incident.created_at.strftime('%Y-%m-%d %H:%M')} UTC",
        _styles["Meta"],
    ))
    story.append(HRFlowable(width="100%", thickness=1.2, color=GOLD, spaceBefore=8, spaceAfter=12))

    # ---- 1. Executive Summary ---------------------------------------------
    _section(story, 1, "Executive Summary")
    story.append(_table([
        ["Incident", incident.id, "Investigation status", analysis.get("intelligence_status") or "ANALYSIS_COMPLETED"],
        ["Classification", classification, "Risk score", f"{incident.risk_score:.2f}"],
        ["Confidence", f"{incident.confidence:.2f}" if incident.confidence is not None else None,
         "Evidence coverage", f"{coverage:.0%}" if coverage is not None else None],
        ["Transaction amount", f"${incident.amount:,.2f}", "Transaction type", incident.transaction_type],
        ["Client name", client_name, "User ID", incident.user_id],
        ["Device", _first_value(payload, "device_name", "device_model") or incident.device_id,
         "Transaction ID", _first_value(payload, "transaction_id", "id")],
        ["Anomaly score", f"{incident.anomaly_score:.2f}", "Recommended disposition",
         governance.get("recommended_disposition")],
    ], [1.15 * inch, 2.0 * inch, 1.45 * inch, 1.6 * inch], header=False))
    story.append(Spacer(1, 8))
    story.append(_paragraph(analysis.get("executive_summary") or incident.explanation))

    # ---- 2. Risk Assessment ------------------------------------------------
    _section(story, 2, "Risk Assessment")
    contributions = assessment.get("score_contributions") or {}
    if contributions:
        story.append(_table([["Persisted contribution", "Value"]] + [
            [key.replace("_", " ").title(), f"{value:.2f}" if isinstance(value, (int, float)) else value]
            for key, value in contributions.items()
        ], [3.8 * inch, 2.4 * inch]))
    else:
        story.append(_paragraph("No persisted risk contributions are available."))

    risk_factors = assessment.get("positive_factors") or []
    if risk_factors:
        story.append(Spacer(1, 6))
        story.append(_paragraph("Risk indicators", "Meta"))
        story.append(_table([["Indicator", "Finding"]] + [
            ["Structured risk signal", factor] for factor in risk_factors
        ], [2.0 * inch, 4.2 * inch]))

    # ---- 3. Transaction Intelligence ---------------------------------------
    _section(story, 3, "Transaction Intelligence")
    transaction_id = _first_value(payload, "transaction_id", "id")
    event_timestamp = _first_value(payload, "timestamp", "transaction_timestamp", "transaction_time", "created_at")
    source_account = _first_value(payload, "source_account", "source_account_id", "from_account")
    destination_account = _first_value(payload, "destination_account", "destination_account_id", "to_account")
    origin_country = _first_value(payload, "origin_country", "source_country", "country")
    destination_country = _first_value(payload, "destination_country", "target_country")
    ip_location = _first_value(payload, "ip", "ip_address", "location", "geo")
    channel = _first_value(payload, "channel", "transaction_channel")
    previous_transaction = _first_value(payload, "previous_transaction", "previous_transaction_id")
    account_age = _first_value(payload, "account_age", "account_age_days")
    story.append(_table([
        ["Attribute", "Value", "Attribute", "Value"],
        ["Transaction ID", transaction_id, "User ID", incident.user_id],
        ["Client name", client_name,
         "Timestamp", event_timestamp or (incident.created_at.isoformat() if incident.created_at else None)],
        ["Transaction type", incident.transaction_type,
         "Narration", _first_value(payload, "transaction_narration", "narration", "description")],
        ["Amount", f"${incident.amount:,.2f}", "Currency", payload.get("currency")],
        ["Source account", source_account, "Destination account", destination_account],
        ["Channel", channel,
         "Origin city / country", " / ".join(str(value) for value in (payload.get("origin_city"), origin_country) if value not in (None, "")) or None],
        ["Destination city / country", " / ".join(str(value) for value in (payload.get("destination_city"), destination_country) if value not in (None, "")) or None,
         "IP address", ip_location],
        ["Device name", _first_value(payload, "device_name", "device_model") or incident.device_id,
         "Device ID", incident.device_id],
        ["Previous transaction", previous_transaction,
         "Previous amount", _first_value(payload, "previous_transaction_amount", "previous_amount")],
        ["Transaction velocity", _first_value(payload, "transaction_velocity_24h", "velocity", "velocity_1h"),
         "Account age (days)", account_age],
        ["Historical pattern", _first_value(payload, "historical_pattern", "transaction_pattern"),
         "Source data", "Original uploaded record retained"],
    ], [1.2 * inch, 1.9 * inch, 1.35 * inch, 1.75 * inch]))

    if payload:
        _section(story, 4, "Uploaded Source Record")
        story.append(_paragraph(
            "Original values retained from the uploaded dataset. The full row is shown for traceability.",
            "Meta",
        ))
        source_rows = [["CSV field", "Uploaded value"]]
        source_rows.extend([
            [str(key).replace("_", " ").strip().title(), value]
            for key, value in payload.items()
        ])
        story.append(_table(source_rows, [2.0 * inch, 4.2 * inch]))

    # ---- 5. Anomaly Findings ------------------------------------------------
    _section(story, 5, "Anomaly Findings")
    findings = analysis.get("findings") or []
    if findings:
        story.append(_table([["Finding", "Severity", "Observed signal", "Rationale", "Evidence status", "Confidence"]] + [
            [
                item.get("finding"), item.get("severity"), item.get("observed_signal"),
                item.get("rationale"),
                "Supported" if item.get("supporting_evidence") else "Not available",
                f"{item.get('confidence'):.2f}" if isinstance(item.get("confidence"), (int, float)) else None,
            ]
            for item in findings
        ], [1.15 * inch, 0.7 * inch, 1.4 * inch, 1.8 * inch, 0.85 * inch, 0.5 * inch]))
    else:
        story.append(_paragraph("No persisted anomaly findings are available."))

    # ---- 6. Evidence ---------------------------------------------------------
    _section(story, 6, "Evidence")
    if structured_evidence:
        story.append(_paragraph("Structured signals", "Meta"))
        story.append(_table([["Source", "Relevance", "Confidence", "Status"]] + [
            [
                item.get("source"), item.get("summary"),
                f"{item.get('confidence'):.2f}" if isinstance(item.get("confidence"), (int, float)) else None,
                (item.get("metadata") or {}).get("evidence_status"),
            ] for item in structured_evidence
        ], [1.45 * inch, 2.85 * inch, 0.9 * inch, 1.0 * inch]))
        story.append(Spacer(1, 6))
    if evidence:
        story.append(_paragraph("Evidence retrieved", "Meta"))
        story.append(_table([["Source", "Summary", "Confidence"]] + [
            [item.get("source"), item.get("summary") or item.get("text"),
             f"{item.get('confidence'):.2f}" if isinstance(item.get("confidence"), (int, float)) else None]
            for item in evidence
        ], [1.45 * inch, 3.85 * inch, 0.9 * inch]))
    else:
        story.append(_paragraph("Evidence gaps", "Meta"))
        story.append(Paragraph(
            "No supporting evidence documents or evidence chunks were retrieved for this incident. "
            "Framework mappings are candidate associations, not evidence-backed findings.",
            _styles["Notice"],
        ))

    # ---- 7. Investigation Reasoning -------------------------------------------
    _section(story, 7, "Investigation Reasoning")
    reasoning = analysis.get("risk_rationale") or []
    if reasoning:
        for number, item in enumerate(reasoning, 1):
            story.append(_paragraph(f"Finding {number} - {item}"))
    else:
        story.append(_paragraph(analysis.get("attack_narrative")))

    # ---- 8. Framework Mapping ---------------------------------------------------
    _section(story, 8, "Framework Mapping")
    framework_groups = (
        ("MITRE ATT&CK", analysis.get("mitre") or []),
        ("NIST", analysis.get("nist") or []),
    )
    evidence_backed_groups = [
        (framework, [
            item for item in entries
            if item.get("status") == "evidence_backed" and item.get("supporting_evidence")
        ])
        for framework, entries in framework_groups
    ]
    if not any(entries for _, entries in evidence_backed_groups):
        story.append(Paragraph(
            "No evidence-backed MITRE ATT&CK or NIST mappings are available for this incident. "
            "Candidate mappings were not promoted because supporting evidence was unavailable.",
            _styles["Notice"],
        ))
        story.append(Spacer(1, 6))
    for framework, entries in evidence_backed_groups:
        story.append(_paragraph(framework))
        story.append(
            _table(_framework_rows(entries, framework), [2.7 * inch, 1.15 * inch, 2.35 * inch])
            if entries else _paragraph("No evidence-backed mappings are available.")
        )
        story.append(Spacer(1, 6))

    # ---- 9. Governance ------------------------------------------------------------
    _section(story, 9, "Governance")
    flags = [flag.strip() for flag in (incident.governance_flags or "").split(",") if flag.strip()]
    story.append(_table([
        ["Governance flags", "\n".join(f"- {flag}" for flag in flags) if flags else "None"],
        ["Evidence sufficiency", governance.get("evidence_sufficiency")],
        ["Human review required", "Yes" if governance.get("human_review_required") else "Not established"],
        ["Automated decision", governance.get("automated_decision") or "NONE"],
        ["Limitations", incident.limitations],
    ], [1.7 * inch, 4.5 * inch], header=False))

    # ---- 10. Recommended Actions -----------------------------------------------------
    _section(story, 10, "Recommended Actions")
    if recommendations:
        for number, action in enumerate(recommendations, 1):
            story.append(_paragraph(f"{number}. {action}"))
    else:
        story.append(Paragraph(
            "No persisted recommendations are available. Investigation analysis should be completed "
            "before relying on this report for operational decision-making.",
            _styles["Notice"],
        ))

    # ---- 11. Disposition ---------------------------------------------------------------
    _section(story, 11, "Disposition")
    story.append(_table([
        ["Risk", classification], ["Evidence", governance.get("evidence_sufficiency")],
        ["Confidence", f"{incident.confidence:.2f}" if incident.confidence is not None else None],
        ["Recommended action", governance.get("recommended_disposition")],
        ["Automated decision", governance.get("automated_decision") or "NONE"],
    ], [2.0 * inch, 4.2 * inch], header=False))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Recommendations are advisory and do not constitute an automated determination of fraud or "
        "criminal activity.",
        _styles["Notice"],
    ))

    decorator = _make_page_decorator(incident_short_id)
    doc.build(
        story,
        onFirstPage=decorator,
        onLaterPages=decorator,
        canvasmaker=_NumberedCanvas,
    )
    return str(path)
