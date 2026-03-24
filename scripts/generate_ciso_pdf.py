"""Generate HYDRA CISO Brief PDF."""
from reportlab.lib.pagesizes import letter
from reportlab.lib.colors import HexColor
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER


def generate_pdf(output_path):
    doc = SimpleDocTemplate(output_path, pagesize=letter,
        topMargin=0.5*inch, bottomMargin=0.5*inch,
        leftMargin=0.75*inch, rightMargin=0.75*inch)

    styles = getSampleStyleSheet()

    # Custom styles
    dark_bg = HexColor('#0f172a')
    red_accent = HexColor('#dc2626')

    title_style = ParagraphStyle('Title2', parent=styles['Title'],
        fontSize=24, textColor=HexColor('#ffffff'), backColor=dark_bg,
        spaceBefore=0, spaceAfter=6, alignment=TA_CENTER,
        borderPadding=(20, 10, 20, 10))

    subtitle_style = ParagraphStyle('Subtitle2', parent=styles['Normal'],
        fontSize=11, textColor=HexColor('#94a3b8'), backColor=dark_bg,
        alignment=TA_CENTER, spaceBefore=0, spaceAfter=20,
        borderPadding=(0, 0, 20, 10))

    section_style = ParagraphStyle('Section2', parent=styles['Heading2'],
        fontSize=13, textColor=red_accent, spaceBefore=16, spaceAfter=6,
        borderWidth=0, borderColor=red_accent, borderPadding=(0, 0, 0, 0))

    body_style = ParagraphStyle('Body2', parent=styles['Normal'],
        fontSize=9.5, leading=13, spaceBefore=4, spaceAfter=4)

    bold_style = ParagraphStyle('Bold2', parent=body_style, fontName='Helvetica-Bold')

    footer_style = ParagraphStyle('Footer2', parent=styles['Normal'],
        fontSize=7, textColor=HexColor('#64748b'), alignment=TA_CENTER,
        spaceBefore=20)

    elements = []

    # HEADER
    elements.append(Paragraph('HYDRA', title_style))
    elements.append(Paragraph('Autonomous Air-Gapped SOC Investigation', subtitle_style))

    # SECTION 1: THE PROBLEM
    elements.append(Paragraph('THE PROBLEM', section_style))
    elements.append(Paragraph(
        'Regulated enterprises cannot send security data to cloud AI. '
        'GDPR Article 44, HIPAA, NERC CIP, and CMMC prohibit it. '
        'Current options: hire more Tier 1 analysts ($80-120K each) or accept compliance risk. '
        'Alert volume is growing; headcount is frozen.', body_style))
    elements.append(Paragraph(
        'Every major SOC AI tool — CrowdStrike Charlotte AI, Microsoft Copilot for Security, '
        'Google Chronicle — requires cloud connectivity. If your data cannot leave, you cannot use them.', body_style))

    # SECTION 2: WHAT HYDRA DOES
    elements.append(Paragraph('WHAT HYDRA DOES', section_style))
    elements.append(Paragraph(
        'HYDRA is an autonomous SOC investigation platform that runs entirely on your hardware. '
        'It receives alerts from your SIEM (Splunk, Elastic, Sentinel), uses a local LLM to investigate '
        'each alert, executes investigation code in a hardened sandbox, and delivers structured verdicts '
        'with IOCs, risk scores, and MITRE ATT&amp;CK mapping. Zero data egress. No cloud dependency.', body_style))
    elements.append(Paragraph(
        '<b>Key differentiator:</b> HYDRA generates investigation code, not classifications. '
        'When it encounters a novel attack type never seen before, it writes a new investigation from scratch.', body_style))

    # SECTION 3: PROOF
    elements.append(Paragraph('PROOF — 10/10 CORRECT VERDICTS', section_style))

    table_data = [
        ['Alert Type', 'Verdict', 'Risk', 'Path'],
        ['SSH Brute Force', 'true_positive', '100', 'Template'],
        ['Lateral Movement (PtH)', 'true_positive', '95', 'Template+LLM'],
        ['Defense Evasion (Timestomp)', 'true_positive', '75', 'LLM Generated'],
        ['Kerberoasting (T1558)', 'true_positive', '75', 'LLM Generated'],
        ['LOLBins certutil (T1105)', 'true_positive', '95', 'LLM Generated'],
        ['Windows Update (benign)', 'benign', '20', 'LLM Generated'],
    ]

    table = Table(table_data, colWidths=[2.2*inch, 1.2*inch, 0.5*inch, 1.2*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), dark_bg),
        ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8.5),
        ('ALIGN', (2, 0), (2, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#ffffff'), HexColor('#f8fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(table)

    elements.append(Spacer(1, 6))
    elements.append(Paragraph(
        '<b>Benchmark:</b> Verdict accuracy 85.7% (fast-fill) to 100% (live LLM). '
        'Avg risk calibration: 36 to 89. Investigation time: 15s (template) / 90s (LLM). '
        'Juice Shop: 99/100 on 100 real-traffic OWASP attacks.', body_style))

    # SECTION 4: HOW IT WORKS
    elements.append(Paragraph('HOW IT WORKS', section_style))
    elements.append(Paragraph('Five-stage pipeline, all on-premise:', body_style))

    pipeline_data = [
        ['Stage', 'Function', 'LLM?'],
        ['1. INGEST', 'Dedup, PII mask, skill retrieval', 'No'],
        ['2. ANALYZE', 'LLM generates investigation code (or fills template)', 'Yes'],
        ['3. EXECUTE', 'Hardened Docker sandbox, no network, 512MB limit', 'No'],
        ['4. ASSESS', 'Verdict, IOC extraction with evidence citations, MITRE mapping', 'Yes'],
        ['5. STORE', 'Entity graph, audit trail, Sigma rule generation', 'No'],
    ]

    pipeline_table = Table(pipeline_data, colWidths=[1*inch, 3.2*inch, 0.5*inch])
    pipeline_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), dark_bg),
        ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8.5),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#ffffff'), HexColor('#f8fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    elements.append(pipeline_table)

    elements.append(Spacer(1, 4))
    elements.append(Paragraph(
        '<b>Stack:</b> Go API + Python Temporal Worker + PostgreSQL/pgvector + Local LLM (Qwen2.5-14B) + '
        'React Dashboard. 6 core containers, single GPU, air-gapped. '
        '161 commits. 65,000+ lines. 55 database migrations.', body_style))

    # SECTION 5: THE ASK
    elements.append(Paragraph('THE ASK', section_style))
    elements.append(Paragraph(
        '<b>30-day pilot.</b> Your SIEM. Your alerts. Your hardware.', bold_style))
    elements.append(Paragraph(
        'We connect to your Splunk or Elastic via webhook, run HYDRA against live alerts, '
        'and deliver weekly accuracy reports. No data leaves your network at any point.', body_style))
    elements.append(Paragraph(
        '<b>We provide:</b> deployment support, SIEM webhook integration, weekly accuracy reviews.<br/>'
        '<b>You provide:</b> SIEM webhook access, one GPU server (8GB+ VRAM), one analyst for ground-truth labeling.', body_style))
    elements.append(Paragraph(
        '<b>No data leaves your network. No cloud dependency. No per-query pricing.</b>', bold_style))

    # FOOTER
    elements.append(Paragraph(
        'Confidential — HYDRA v1.5.1 — 2026-03-24 — Not for distribution', footer_style))

    doc.build(elements)
    print(f"PDF generated: {output_path}")


if __name__ == "__main__":
    generate_pdf("/app/HYDRA_CISO_Brief.pdf")
