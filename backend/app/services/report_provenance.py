"""Add a first-page dataset provenance summary to generated incident PDFs."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

from pypdf import PdfReader, PdfWriter
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.db.models import Incident
from app.services.dataset_provenance import incident_provenance


def add_data_provenance_page(pdf_path: str, incident: Incident) -> str:
    """Prepend a stable provenance summary using values persisted on the incident."""
    provenance = (incident.analysis_json or {}).get("data_provenance") or incident_provenance(incident)
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.7 * inch,
        leftMargin=0.7 * inch,
        topMargin=0.8 * inch,
        bottomMargin=0.7 * inch,
        title=f"Data Provenance - {incident.id[:8]}",
    )
    styles = getSampleStyleSheet()

    def cell(value) -> str:
        return "Not recorded" if value in (None, "") else str(value)

    rows = [
        ["Source", cell(provenance.get("source_label") or provenance.get("source")),
         "Dataset", cell(provenance.get("dataset_name"))],
        ["Dataset ID", cell(provenance.get("dataset_id")),
         "Version", cell(provenance.get("dataset_version"))],
        ["Dataset records", cell(provenance.get("records_analyzed")),
         "Data type", "Synthetic demonstration data" if provenance.get("synthetic") else "Uploaded dataset"],
        ["Tenant", cell(provenance.get("tenant_name") or incident.tenant_id),
         "Incident", cell(incident.id)],
    ]
    story = [
        Paragraph("FINSECAI | SOC COMMAND CENTER", styles["Normal"]),
        Spacer(1, 12),
        Paragraph("Data Provenance", styles["Title"]),
        Paragraph("Dataset recorded with this investigation at analysis time.", styles["BodyText"]),
        Spacer(1, 20),
        Table(rows, colWidths=[1.2 * inch, 2.0 * inch, 1.1 * inch, 2.0 * inch], repeatRows=0,
           style=TableStyle([
               ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E2E8F0")),
               ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#E2E8F0")),
               ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0F172A")),
               ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
               ("VALIGN", (0, 0), (-1, -1), "TOP"),
               ("LEFTPADDING", (0, 0), (-1, -1), 7),
               ("RIGHTPADDING", (0, 0), (-1, -1), 7),
               ("TOPPADDING", (0, 0), (-1, -1), 8),
               ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
           ])),
    ]
    doc.build(story)

    target = Path(pdf_path)
    temporary = target.with_name(f"{target.stem}.provenance{target.suffix}")
    source_reader = PdfReader(str(target))
    buffer.seek(0)
    provenance_reader = PdfReader(buffer)
    writer = PdfWriter()
    writer.add_page(provenance_reader.pages[0])
    for page in source_reader.pages:
        writer.add_page(page)
    with temporary.open("wb") as output:
        writer.write(output)
    temporary.replace(target)
    return str(target)
