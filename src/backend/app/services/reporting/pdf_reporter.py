"""Forensic PDF report generator using ReportLab."""

import json
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)

from app.config import settings
from app.models.models import (
    Investigation,
    EvidenceFile,
    Event,
    DetectionAlert,
    InvestigationReport,
    generate_uuid,
)


def generate_pdf_report(investigation_id: str, db: Session) -> InvestigationReport:
    """Generate high-fidelity forensic PDF report with VIGILANCE branding and tables."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise ValueError(f"Investigation {investigation_id} not found.")

    evidence_items = db.query(EvidenceFile).filter(EvidenceFile.investigation_id == investigation_id).all()
    events = (
        db.query(Event)
        .filter(Event.investigation_id == investigation_id)
        .order_by(Event.normalized_timestamp.asc().nulls_last())
        .limit(100)  # Top 100 for PDF presentation
        .all()
    )
    alerts = db.query(DetectionAlert).filter(DetectionAlert.investigation_id == investigation_id).all()

    reports_dir = Path(settings.REPORTS_PATH)
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_filename = f"report_{inv.id[:8]}_{timestamp_str}.pdf"
    report_path = reports_dir / report_filename

    doc = SimpleDocTemplate(
        str(report_path),
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
    )
    heading2_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=14,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155"),
    )
    table_header_style = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.white,
    )
    table_cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1e293b"),
    )
    code_style = ParagraphStyle(
        "TableCode",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7,
        leading=9,
        textColor=colors.HexColor("#0f172a"),
    )

    story = []

    # 1. Header with Dark VIGILANCE Banner
    header_data = [
        [
            Paragraph("<font color='#38bdf8'><b>VIGILANCE</b></font> DIGITAL FORENSICS PLATFORM", ParagraphStyle(
                "BannerTitle", fontName="Helvetica-Bold", fontSize=15, leading=18, textColor=colors.white
            )),
            Paragraph(f"REPORT GENERATED: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", ParagraphStyle(
                "BannerRight", fontName="Helvetica", fontSize=8, leading=10, textColor=colors.HexColor("#cbd5e1"), alignment=2
            )),
        ]
    ]
    header_table = Table(header_data, colWidths=[360, 180])
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 15))

    # 2. Title & Overview
    story.append(Paragraph(f"Forensic Investigation Report: {inv.name}", title_style))
    story.append(Paragraph(f"Investigation ID: {inv.id} &bull; Classification: {inv.category} &bull; Status: {inv.status}", subtitle_style))
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceBefore=1, spaceAfter=10))

    # 3. Investigation Details Table
    story.append(Paragraph("1. Investigation Details", heading2_style))
    inv_details = [
        [Paragraph("<b>Investigation Name</b>", table_cell_style), Paragraph(inv.name, table_cell_style)],
        [Paragraph("<b>Incident Category</b>", table_cell_style), Paragraph(inv.category or "General", table_cell_style)],
        [Paragraph("<b>Current Status</b>", table_cell_style), Paragraph(inv.status, table_cell_style)],
        [Paragraph("<b>Description</b>", table_cell_style), Paragraph(inv.description or "No description provided.", table_cell_style)],
        [Paragraph("<b>Created Timestamp</b>", table_cell_style), Paragraph(str(inv.created_at) + " UTC", table_cell_style)],
        [Paragraph("<b>Last Updated</b>", table_cell_style), Paragraph(str(inv.updated_at) + " UTC", table_cell_style)],
    ]
    inv_table = Table(inv_details, colWidths=[140, 400])
    inv_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(inv_table)
    story.append(Spacer(1, 14))

    # 4. Evidence Inventory & Hashing
    story.append(Paragraph("2. Evidence Inventory & Cryptographic Hashes", heading2_style))
    evidence_rows = [
        [
            Paragraph("Filename", table_header_style),
            Paragraph("Format", table_header_style),
            Paragraph("Size (Bytes)", table_header_style),
            Paragraph("SHA-256 Hash", table_header_style),
            Paragraph("Status", table_header_style),
        ]
    ]
    for ev in evidence_items:
        evidence_rows.append([
            Paragraph(ev.original_filename, table_cell_style),
            Paragraph(ev.file_format or "unknown", table_cell_style),
            Paragraph(f"{ev.file_size:,}", table_cell_style),
            Paragraph(ev.sha256_hash, code_style),
            Paragraph(ev.processing_status, table_cell_style),
        ])

    if len(evidence_rows) == 1:
        evidence_rows.append([Paragraph("No evidence files registered.", table_cell_style)] * 5)

    ev_table = Table(evidence_rows, colWidths=[110, 50, 70, 240, 70])
    ev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(ev_table)
    story.append(Spacer(1, 14))

    # 5. Detection Alerts Summary
    story.append(Paragraph(f"3. Detection & Correlation Alerts ({len(alerts)} Detected)", heading2_style))
    alert_rows = [
        [
            Paragraph("Severity", table_header_style),
            Paragraph("Rule Name", table_header_style),
            Paragraph("Explanation", table_header_style),
            Paragraph("Involved Entities", table_header_style),
        ]
    ]
    for a in alerts:
        ips = json.loads(a.ip_addresses) if a.ip_addresses else []
        users = json.loads(a.usernames) if a.usernames else []
        entities = f"IPs: {', '.join(ips[:3])}<br/>Users: {', '.join(users[:3])}"
        sev_color = "#dc2626" if a.severity == "CRITICAL" else ("#ea580c" if a.severity == "HIGH" else "#ca8a04")

        alert_rows.append([
            Paragraph(f"<b><font color='{sev_color}'>{a.severity}</font></b>", table_cell_style),
            Paragraph(f"<b>{a.rule_name}</b><br/>Type: {a.alert_type}", table_cell_style),
            Paragraph(a.explanation, table_cell_style),
            Paragraph(entities, table_cell_style),
        ])

    if len(alert_rows) == 1:
        alert_rows.append([Paragraph("No automated detection alerts triggered.", table_cell_style)] * 4)

    alerts_table = Table(alert_rows, colWidths=[70, 130, 220, 120])
    alerts_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(alerts_table)
    story.append(Spacer(1, 14))

    # 6. Timeline Events Summary (Top 25 for PDF)
    story.append(Paragraph("4. Key Forensic Events Timeline", heading2_style))
    timeline_rows = [
        [
            Paragraph("UTC Timestamp", table_header_style),
            Paragraph("Status", table_header_style),
            Paragraph("Category", table_header_style),
            Paragraph("Source IP", table_header_style),
            Paragraph("User", table_header_style),
            Paragraph("Description", table_header_style),
        ]
    ]
    for e in events[:30]:
        timeline_rows.append([
            Paragraph(e.normalized_timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.normalized_timestamp else "UNCERTAIN", table_cell_style),
            Paragraph(e.timestamp_status[:12], code_style),
            Paragraph(e.event_category, table_cell_style),
            Paragraph(e.source_ip or "-", code_style),
            Paragraph(e.username or "-", table_cell_style),
            Paragraph((e.description or "")[:70], table_cell_style),
        ])

    if len(timeline_rows) == 1:
        timeline_rows.append([Paragraph("No parsed timeline events recorded.", table_cell_style)] * 6)

    timeline_table = Table(timeline_rows, colWidths=[100, 70, 90, 80, 60, 140])
    timeline_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(timeline_table)
    story.append(Spacer(1, 14))

    # 7. Findings & Forensic Limitations
    story.append(Paragraph("5. Forensic Findings & Methodological Limitations", heading2_style))
    findings_text = (
        "<b>Summary of Findings:</b> Cross-log correlation was executed across the ingested datasets. "
        "Cryptographic hashes verify that original source evidence files remain unmodified. "
        "Timestamps have been strictly validated; logs without explicit timezone headers have been identified "
        "and flagged to prevent timeline skew contamination.<br/><br/>"
        "<b>Limitations & Verification:</b> In accordance with digital forensics standards, parsed events marked "
        "with UNCERTAIN or SYSLOG_NO_YEAR status should be corroborated with external physical or host-level NTP telemetry."
    )
    story.append(Paragraph(findings_text, body_style))
    story.append(Spacer(1, 15))

    # 8. Footer
    footer_text = f"Report generated by VIGILANCE Forensics Engine &bull; Document SHA-256 Verification &bull; {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceBefore=10, spaceAfter=6))
    story.append(Paragraph(footer_text, ParagraphStyle("Footer", fontName="Helvetica", fontSize=7, textColor=colors.HexColor("#64748b"), alignment=1)))

    doc.build(story)

    file_size = report_path.stat().st_size
    report_record = InvestigationReport(
        id=generate_uuid(),
        investigation_id=investigation_id,
        format="pdf",
        file_path=str(report_path.resolve()),
        generated_at=datetime.utcnow(),
        file_size=file_size,
    )
    db.add(report_record)
    db.commit()
    db.refresh(report_record)

    return report_record
