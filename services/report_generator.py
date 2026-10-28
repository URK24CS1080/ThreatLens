"""
PDF Report Generator Module.
Generates comprehensive, professionally formatted cybersecurity assessment PDF reports
using ReportLab Platypus. Suitable for academic presentation and audit reporting.
"""

from pathlib import Path
from typing import Dict, Any, List
import io
import re
import html

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas
from config import Config


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and display total page count."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages):
        self.saveState()
        # Top Header line
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(40, letter[1] - 35, letter[0] - 40, letter[1] - 35)

        # Header Text
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#0f172a"))
        self.drawString(40, letter[1] - 30, "THREATLENS - WEB SECURITY RECONNAISSANCE & THREAT INTELLIGENCE")
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        self.drawRightString(letter[0] - 40, letter[1] - 30, "Security Audit & Risk Assessment")

        # Bottom Footer line
        self.line(40, 40, letter[0] - 40, 40)
        self.drawString(40, 28, "THREATLENS SECURITY PLATFORM - CONFIDENTIAL AUDIT ASSESSMENT")
        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.drawRightString(letter[0] - 40, 28, page_str)
        self.restoreState()


def get_severity_color(severity: str) -> colors.Color:
    """Returns a ReportLab color corresponding to the finding severity."""
    sev = severity.lower()
    if sev == "critical":
        return colors.HexColor("#d90429")
    elif sev == "high":
        return colors.HexColor("#e85d04")
    elif sev == "medium":
        return colors.HexColor("#f48c06")
    elif sev == "low":
        return colors.HexColor("#0077b6")
    else:
        return colors.HexColor("#475569")


def generate_pdf_report(scan_data: Dict[str, Any], output_path: Path) -> Path:
    """
    Constructs and writes the complete security report PDF to output_path.
    Returns output_path on success.
    """
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=50,
        bottomMargin=50
    )

    styles = getSampleStyleSheet()

    # Custom typography styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4
    )
    
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
        spaceAfter=12
    )

    h1_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )

    code_style = ParagraphStyle(
        "ReportCode",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1e293b")
    )

    story = []

    # Title & Metadata
    domain = scan_data.get("domain", "Unknown Domain")
    target_url = scan_data.get("target_url", "")
    created_at = scan_data.get("created_at", "N/A")
    risk_score = scan_data.get("risk_score", 100)
    risk_grade = scan_data.get("risk_grade", "A")

    story.append(Paragraph("Security Assessment & Threat Intelligence Report", title_style))
    story.append(Paragraph(f"Target: <b>{domain}</b> &bull; Audit Date: <b>{created_at}</b>", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=14))

    # 1. Executive Summary Table
    story.append(Paragraph("1. Executive Summary", h1_style))
    
    grade_color = colors.HexColor("#16a34a") if risk_grade in ("A", "B") else (
        colors.HexColor("#ca8a04") if risk_grade == "C" else colors.HexColor("#dc2626")
    )

    exec_summary_data = [
        [
            Paragraph("<b>Target URL</b>", body_style),
            Paragraph(target_url, code_style),
            Paragraph("<b>Overall Posture Score</b>", body_style),
            Paragraph(f"<b><font size=14 color='{grade_color.hexval()}'>{risk_score}/100</font> (Grade {risk_grade})</b>", body_style)
        ],
        [
            Paragraph("<b>Resolved IP</b>", body_style),
            Paragraph(scan_data.get("ip_address") or "N/A", code_style),
            Paragraph("<b>Total Findings</b>", body_style),
            Paragraph(f"<b>{scan_data.get('total_findings', 0)}</b> items identified", body_style)
        ],
        [
            Paragraph("<b>Audit Status</b>", body_style),
            Paragraph(scan_data.get("status", "completed").capitalize(), body_style),
            Paragraph("<b>Scan Duration</b>", body_style),
            Paragraph(f"{scan_data.get('scan_duration_seconds', 0)} seconds", body_style)
        ]
    ]

    t_exec = Table(exec_summary_data, colWidths=[1.3*inch, 2.2*inch, 1.4*inch, 2.1*inch])
    t_exec.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('PADDING', (0,0), (-1,-1), 6),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(t_exec)
    story.append(Spacer(1, 10))

    # Findings Breakdown Bar/Table
    crit = scan_data.get("critical_count", 0)
    high = scan_data.get("high_count", 0)
    med = scan_data.get("medium_count", 0)
    low = scan_data.get("low_count", 0)
    info = scan_data.get("info_count", 0)

    sev_table_data = [
        [
            Paragraph("<b>Critical</b>", body_style),
            Paragraph("<b>High</b>", body_style),
            Paragraph("<b>Medium</b>", body_style),
            Paragraph("<b>Low</b>", body_style),
            Paragraph("<b>Informational</b>", body_style)
        ],
        [
            Paragraph(f"<b><font color='#d90429' size=12>{crit}</font></b>", body_style),
            Paragraph(f"<b><font color='#e85d04' size=12>{high}</font></b>", body_style),
            Paragraph(f"<b><font color='#f48c06' size=12>{med}</font></b>", body_style),
            Paragraph(f"<b><font color='#0077b6' size=12>{low}</font></b>", body_style),
            Paragraph(f"<b><font color='#475569' size=12>{info}</font></b>", body_style),
        ]
    ]
    t_sev = Table(sev_table_data, colWidths=[1.4*inch]*5)
    t_sev.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
        ('BACKGROUND', (0,1), (-1,1), colors.HexColor("#ffffff")),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_sev)
    story.append(Spacer(1, 12))

    # 2. Reconnaissance Results
    recon = scan_data.get("recon", {})
    story.append(Paragraph("2. Reconnaissance & Fingerprinting", h1_style))
    
    tls_cert = recon.get("tls_cert", {})
    tls_desc = "None (Plain HTTP)"
    if tls_cert.get("has_tls"):
        tls_desc = f"{tls_cert.get('tls_version', 'TLS')} (Issuer: {tls_cert.get('issuer', 'Unknown')}, Expiry: {tls_cert.get('valid_to', 'N/A')})"

    techs = recon.get("technologies", [])
    tech_str = ", ".join([t.get("name") for t in techs]) if techs else "No distinctive technology headers revealed"

    recon_table_data = [
        [Paragraph("<b>HTTP Status</b>", body_style), Paragraph(str(recon.get("http_status", "N/A")), body_style)],
        [Paragraph("<b>Page Title</b>", body_style), Paragraph(recon.get("page_title", "N/A")[:70], body_style)],
        [Paragraph("<b>Server Header</b>", body_style), Paragraph(recon.get("server_header", "Not disclosed"), code_style)],
        [Paragraph("<b>HTTPS / TLS</b>", body_style), Paragraph(tls_desc, body_style)],
        [Paragraph("<b>Detected Tech</b>", body_style), Paragraph(tech_str, body_style)],
    ]

    t_recon = Table(recon_table_data, colWidths=[1.8*inch, 5.2*inch])
    t_recon.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f1f5f9")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('PADDING', (0,0), (-1,-1), 5),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(t_recon)
    story.append(Spacer(1, 12))

    # 3. Security Findings
    story.append(Paragraph("3. Detailed Security Configuration Findings", h1_style))
    findings = scan_data.get("findings", [])

    if not findings:
        story.append(Paragraph("No configuration weaknesses or findings were recorded during this scan.", body_style))
    else:
        for idx, f in enumerate(findings, 1):
            sev = f.get("severity", "Informational")
            sev_col = get_severity_color(sev)

            finding_header = [
                [
                    Paragraph(f"<b>#{idx}. {f.get('title')}</b>", ParagraphStyle(
                        "FH", parent=body_style, fontName="Helvetica-Bold", fontSize=9, textColor=colors.HexColor("#0f172a")
                    )),
                    Paragraph(f"<b><font color='{sev_col.hexval()}'>[{sev.upper()}]</font></b> &bull; {f.get('category')}", ParagraphStyle(
                        "FS", parent=body_style, alignment=2, fontSize=8
                    ))
                ]
            ]
            t_fh = Table(finding_header, colWidths=[5.0*inch, 2.0*inch])
            t_fh.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
                ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                ('TOPPADDING', (0,0), (-1,-1), 3),
            ]))

            detail_data = [
                [Paragraph("<b>Evidence:</b>", body_style), Paragraph(f.get("evidence", "N/A"), code_style)],
                [Paragraph("<b>Why it matters:</b>", body_style), Paragraph(f.get("explanation", "N/A"), body_style)],
                [Paragraph("<b>Remediation:</b>", body_style), Paragraph(f.get("remediation", "N/A"), body_style)]
            ]
            t_fd = Table(detail_data, colWidths=[1.2*inch, 5.8*inch])
            t_fd.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
                ('PADDING', (0,0), (-1,-1), 4),
                ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f8fafc")),
            ]))

            finding_block = [t_fh, t_fd, Spacer(1, 8)]
            story.append(KeepTogether(finding_block))

    # 4. Open Ports & Services (if enabled)
    story.append(Paragraph("4. Authorized Port & Service Discovery", h1_style))
    open_ports = recon.get("open_ports", [])
    port_enabled = scan_data.get("port_scan_enabled", 0)

    if not port_enabled:
        story.append(Paragraph("Port scanning was disabled or not authorized for this scan session.", body_style))
    elif not open_ports:
        story.append(Paragraph("Scan completed: No open ports discovered among probed standard common ports.", body_style))
    else:
        port_rows = [
            [
                Paragraph("<b>Port</b>", body_style),
                Paragraph("<b>Service</b>", body_style),
                Paragraph("<b>State</b>", body_style),
                Paragraph("<b>Version / Probe Details</b>", body_style)
            ]
        ]
        for p in open_ports:
            port_rows.append([
                Paragraph(str(p.get("port")), code_style),
                Paragraph(str(p.get("service")), body_style),
                Paragraph(str(p.get("state")).upper(), body_style),
                Paragraph(str(p.get("version", "N/A")), body_style),
            ])
        t_ports = Table(port_rows, colWidths=[1.0*inch, 2.2*inch, 1.0*inch, 2.8*inch])
        t_ports.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_ports)

    story.append(Spacer(1, 10))

    # 5. Threat Intelligence Results
    story.append(Paragraph("5. Threat Intelligence Records", h1_style))
    threat_intel = recon.get("threat_intel", {})
    providers = threat_intel.get("providers", {})
    
    ti_rows = [
        [
            Paragraph("<b>Intelligence Source</b>", body_style),
            Paragraph("<b>Status</b>", body_style),
            Paragraph("<b>Match Category</b>", body_style),
            Paragraph("<b>Details</b>", body_style)
        ]
    ]

    for p_key, p_val in providers.items():
        if isinstance(p_val, dict):
            p_name = p_val.get("provider", p_key.replace("_", " ").title())
            p_status = p_val.get("status", "N/A")
            p_match = p_val.get("threat_category", "None") or "None"
            p_details = p_val.get("details", "")
            if not p_details and p_val.get("indicators"):
                p_details = f"{len(p_val.get('indicators'))} heuristic indicators noted."
            
            ti_rows.append([
                Paragraph(p_name, body_style),
                Paragraph(p_status, body_style),
                Paragraph(p_match, body_style),
                Paragraph(p_details or "No records", body_style)
            ])

    t_ti = Table(ti_rows, colWidths=[1.6*inch, 1.4*inch, 1.4*inch, 2.6*inch])
    t_ti.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_ti)
    story.append(Spacer(1, 14))

    # 6. AI-Assisted Security Analysis & Remediation Roadmap
    story.append(Paragraph("6. AI-Assisted Security Analysis & Remediation Roadmap", h1_style))
    
    ai_doc = scan_data.get("ai_analysis") or {}
    ai_text = ""
    ai_provider = "ThreatLens Built-in Engine"
    if isinstance(ai_doc, dict):
        ai_text = ai_doc.get("executive_summary") or ai_doc.get("natural_language_report") or ""
        ai_provider = ai_doc.get("provider", "builtin").capitalize()
    elif isinstance(ai_doc, str):
        ai_text = ai_doc
    if not ai_text:
        ai_text = recon.get("ai_explanation") or "Automated AI synthesis unavailable for this scan."

    story.append(Paragraph(
        f"<i>AI Engine: <b>{ai_provider}</b> &bull; Note: AI-synthesized findings are advisory explanations and should be validated by human analysts.</i>",
        ParagraphStyle("AIMeta", parent=body_style, fontSize=8, textColor=colors.HexColor("#0284c7"), spaceAfter=6)
    ))
    # Cleanly format AI text without breaking ReportLab's XML parser
    ai_paragraphs = [p.strip() for p in ai_text.split("\n\n") if p.strip()]
    for p in ai_paragraphs[:6]:
        # Strip raw markdown symbols
        clean_p = re.sub(r"^[#\s\-*•]+", "", p)
        clean_p = re.sub(r"[*_`]", "", clean_p)
        escaped_p = html.escape(clean_p)
        story.append(Paragraph(escaped_p, ParagraphStyle("AIText", parent=body_style, leading=13)))
        story.append(Spacer(1, 4))
    story.append(Spacer(1, 10))

    # 7. Audit Limitations & Methodology
    story.append(Paragraph("7. Audit Limitations & Methodology Notice", h1_style))
    disclaimer_text = (
        "<b>Important Academic & Audit Disclaimer:</b> This security assessment is based exclusively on non-destructive "
        "passive observations, observable HTTP headers, TLS certificate negotiation, and authorized port probing. "
        "The calculated risk score is a comparative prioritization tool, NOT a guarantee of safety or freedom from vulnerabilities. "
        "External threat intelligence queries reflect available database feeds at the time of execution. "
        "This tool is designed strictly for educational and authorized defensive auditing."
    )
    story.append(Paragraph(disclaimer_text, ParagraphStyle(
        "Disclaimer", parent=body_style, fontSize=8, leading=11, textColor=colors.HexColor("#64748b")
    )))

    # Build document
    doc.build(story, canvasmaker=NumberedCanvas)
    return output_path
