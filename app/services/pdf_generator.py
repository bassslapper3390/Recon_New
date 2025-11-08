from pathlib import Path
from typing import Dict, List, Any, Optional
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime


def generate_pdf_report(
    request: Dict[str, Any],
    findings: Dict[str, List[Dict[str, Any]]],
    passive: Dict[str, Any],
    tools: List[Dict[str, Any]],
    output_path: Path
) -> bool:
    """Generate a PDF report from the scan results"""
    try:
        doc = SimpleDocTemplate(str(output_path), pagesize=letter)
        story = []
        
        # Define styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=20
        )
        
        subheading_style = ParagraphStyle(
            'CustomSubHeading',
            parent=styles['Heading3'],
            fontSize=14,
            textColor=colors.HexColor('#495057'),
            spaceAfter=10,
            spaceBefore=15
        )
        
        normal_style = styles['Normal']
        code_style = ParagraphStyle(
            'Code',
            parent=styles['Code'],
            fontSize=8,
            leading=10
        )
        
        # Title
        story.append(Paragraph("Reconnaissance Report", title_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Target information
        target = request.get('domain') or request.get('ip') or 'N/A'
        story.append(Paragraph(f"<b>Target:</b> {target}", normal_style))
        story.append(Paragraph(f"<b>Report Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Findings section
        findings = findings or {}
        if findings and len(findings) > 0:
            story.append(Paragraph("Key Findings", heading_style))
            
            total_findings = sum(len(cat_findings) for cat_findings in findings.values())
            story.append(Paragraph(f"<b>Total Findings:</b> {total_findings}", normal_style))
            story.append(Spacer(1, 0.2*inch))
            
            for category, category_findings in findings.items():
                story.append(Paragraph(f"{category} ({len(category_findings)})", subheading_style))
                
                # Create table for findings
                table_data = [['Type', 'Severity', 'Value', 'Source']]
                
                for finding in category_findings:
                    if not isinstance(finding, dict):
                        continue
                    finding_type = str(finding.get('type', 'N/A'))[:50]
                    severity = str(finding.get('severity', 'info'))[:20]
                    value = str(finding.get('value', ''))[:200]  # Limit length
                    source = str(finding.get('source', 'N/A'))[:50]
                    
                    table_data.append([
                        finding_type,
                        severity.upper(),
                        value,
                        source
                    ])
                
                # Only create table if there are findings (more than just header)
                if len(table_data) > 1:
                    # Create table
                    findings_table = Table(table_data, colWidths=[1.2*inch, 1*inch, 3.5*inch, 1.3*inch])
                    findings_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 1), (-1, -1), 8),
                        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
                    ]))
                    
                    story.append(findings_table)
                    story.append(Spacer(1, 0.3*inch))
        else:
            story.append(Paragraph("Key Findings", heading_style))
            story.append(Paragraph("No findings extracted from this scan.", normal_style))
            story.append(Spacer(1, 0.2*inch))
        
        story.append(PageBreak())
        
        # Passive reconnaissance section
        story.append(Paragraph("Passive Reconnaissance", heading_style))
        
        if passive.get('dns'):
            story.append(Paragraph("DNS Records", subheading_style))
            dns_text = str(passive['dns'])[:2000]  # Limit length
            story.append(Paragraph(dns_text.replace('\n', '<br/>'), code_style))
            story.append(Spacer(1, 0.2*inch))
        
        if passive.get('whois'):
            story.append(Paragraph("WHOIS Information", subheading_style))
            whois_text = str(passive['whois'])[:2000]  # Limit length
            story.append(Paragraph(whois_text.replace('\n', '<br/>'), code_style))
            story.append(Spacer(1, 0.2*inch))
        
        if passive.get('ssl'):
            story.append(Paragraph("SSL Information", subheading_style))
            ssl_text = str(passive['ssl'])[:2000]  # Limit length
            story.append(Paragraph(ssl_text.replace('\n', '<br/>'), code_style))
            story.append(Spacer(1, 0.2*inch))
        
        story.append(PageBreak())
        
        # Tools section
        story.append(Paragraph("Tool Outputs", heading_style))
        
        for tool in tools:
            tool_name = tool.get('name', 'Unknown')
            success = tool.get('success', False)
            status = "OK" if success else "FAILED"
            
            story.append(Paragraph(f"{tool_name} - {status}", subheading_style))
            
            output = tool.get('output') or tool.get('error') or 'No output available'
            output_text = str(output)[:1500]  # Limit length for PDF
            story.append(Paragraph(output_text.replace('\n', '<br/>'), code_style))
            story.append(Spacer(1, 0.2*inch))
        
        # Build PDF
        doc.build(story)
        return True
        
    except Exception as e:
        print(f"Error generating PDF: {e}")
        return False

