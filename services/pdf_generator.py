from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import os
import datetime


def generate(result: dict, output_path: str = "report.pdf") -> str:
    """
    Generate a professional PDF security report.
    Returns the path of the generated PDF.
    """

    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()

    story = []

    story.append(Paragraph("AI Web Security Analysis Report", styles['Title']))
    story.append(Spacer(1, 20))

    story.append(Paragraph(f"<b>Analyzed URL:</b> {result.get('final_url','')}", styles['Normal']))
    story.append(Paragraph(f"<b>Date:</b> {datetime.datetime.now()}", styles['Normal']))
    story.append(Spacer(1, 20))

    story.append(Paragraph("<b>Risk Summary</b>", styles['Heading2']))
    story.append(Paragraph(f"Risk Level: {result.get('risk_level')}", styles['Normal']))
    story.append(Paragraph(f"Dark Pattern Score: {result.get('dark_pattern_score')}", styles['Normal']))
    story.append(Paragraph(f"Phishing Score: {result.get('phishing_score')}", styles['Normal']))
    story.append(Paragraph(f"Total Score: {result.get('total_score')}", styles['Normal']))
    story.append(Spacer(1, 20))

    story.append(Paragraph("<b>Verdict</b>", styles['Heading2']))
    story.append(Paragraph(result.get('verdict_message', ''), styles['Normal']))
    story.append(Spacer(1, 20))

    indicators = result.get("indicators", [])
    if indicators:
        story.append(Paragraph("<b>Detected Indicators</b>", styles['Heading2']))
        for item in indicators:
            story.append(Paragraph(f"• {item}", styles['Normal']))
            story.append(Spacer(1, 6))

    doc.build(story)

    return os.path.abspath(output_path)