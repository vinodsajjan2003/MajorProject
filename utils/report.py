import os
import tempfile
from fpdf import FPDF
from datetime import datetime
from app import app
import logging
import json

class ThreatReportPDF(FPDF):
    """Custom PDF class for threat reports with headers and footers"""
    
    def __init__(self):
        # Initialize with utf8 encoding for better character support
        super().__init__(orientation='P', unit='mm', format='A4')
    
    def header(self):
        # Logo - if you had a logo, you'd add it here
        # self.image('logo.png', 10, 8, 33)
        
        # Set font for the header
        self.set_font('Arial', 'B', 15)
        
        # Title
        self.cell(0, 10, 'Dark Web Threat Detection Report', 0, 1, 'C')
        
        # Line break
        self.ln(5)
    
    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        
        # Set font for the footer
        self.set_font('Arial', 'I', 8)
        
        # Page number
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', 0, 0, 'C')
        
        # Copyright line
        self.set_y(-20)
        self.cell(0, 10, 'CONFIDENTIAL - FOR AUTHORIZED USE ONLY', 0, 1, 'C')

def clean_text_for_pdf(text):
    """Clean text to ensure it is compatible with PDF generation"""
    if not text:
        return ""
    
    # Replace Unicode characters that cause encoding issues
    replacements = {
        '\u2014': '-',  # em dash
        '\u2013': '-',  # en dash
        '\u2018': "'",  # left single quote
        '\u2019': "'",  # right single quote
        '\u201c': '"',  # left double quote
        '\u201d': '"',  # right double quote
        '\u2022': '*',  # bullet
        '\u2026': '...',  # ellipsis
        '\u00a0': ' ',  # non-breaking space
    }
    
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    
    # Remove any other non-ASCII characters
    text = ''.join(c if ord(c) < 128 else ' ' for c in text)
    return text

def generate_pdf_report(scan):
    """
    Generate a PDF report for a scan with detailed threat information.
    
    Args:
        scan: The Scan object containing threat details
    
    Returns:
        str: Path to the generated PDF file
    """
    try:
        # Create a PDF object with total page numbers
        pdf = ThreatReportPDF()
        pdf.alias_nb_pages()  # Will replace {nb} with total pages
        pdf.add_page()
        
        # Date and time
        pdf.set_font("Arial", "I", 10)
        pdf.cell(0, 6, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, "R")
        pdf.ln(5)
        
        # Executive Summary
        pdf.set_font("Arial", "B", 13)
        pdf.cell(0, 10, "Executive Summary", 0, 1)
        pdf.set_font("Arial", "", 11)
        
        # Clean and prepare text for PDF
        url = clean_text_for_pdf(scan.url)
        threat_type = clean_text_for_pdf(scan.threat_type)
        severity = clean_text_for_pdf(scan.severity) if hasattr(scan, 'severity') and scan.severity else "Medium"
        confidence_score = float(scan.confidence_score) if hasattr(scan, 'confidence_score') and scan.confidence_score else 0.8
        recommendation = clean_text_for_pdf(scan.recommendation) if hasattr(scan, 'recommendation') and scan.recommendation else "Monitor and investigate the potential threat."
        content = clean_text_for_pdf(scan.content) if hasattr(scan, 'content') and scan.content else "No content available."
        
        # Create summary based on threat type and severity
        summary = f"Analysis of the URL {url} has identified it as a potential source of {threat_type.lower()} threats. "
        
        if severity == "High":
            summary += f"This threat is classified as HIGH severity with a confidence score of {confidence_score:.2f}, indicating an immediate risk that requires prompt action."
        elif severity == "Medium":
            summary += f"This threat is classified as MEDIUM severity with a confidence score of {confidence_score:.2f}, suggesting moderate risk that should be addressed."
        else:
            summary += f"This threat is classified as LOW severity with a confidence score of {confidence_score:.2f}, indicating minimal immediate risk but should still be monitored."
        
        pdf.multi_cell(0, 6, summary)
        pdf.ln(5)
        
        # URL information section
        pdf.set_font("Arial", "B", 13)
        pdf.cell(0, 10, "URL Information", 0, 1)
        pdf.set_font("Arial", "", 11)
        
        # URL details table
        pdf.set_fill_color(240, 240, 240)  # Light gray background
        pdf.cell(40, 10, "URL:", 1, 0, 'L', True)
        pdf.cell(150, 10, url, 1, 1, 'L')
        pdf.cell(40, 10, "Scan Date:", 1, 0, 'L', True)
        pdf.cell(150, 10, scan.created_at.strftime('%Y-%m-%d %H:%M:%S') if hasattr(scan, 'created_at') else datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 1, 1, 'L')
        pdf.ln(5)
        
        # Threat Analysis section
        pdf.set_font("Arial", "B", 13)
        pdf.cell(0, 10, "Threat Analysis", 0, 1)
        
        # Create a colored box based on severity
        if severity == "High":
            pdf.set_fill_color(255, 200, 200)  # Light red
        elif severity == "Medium":
            pdf.set_fill_color(255, 235, 175)  # Light orange/yellow
        else:
            pdf.set_fill_color(200, 255, 200)  # Light green
            
        # Create a table for threat details
        pdf.set_font("Arial", "B", 11)
        pdf.cell(190, 10, "Threat Details", 1, 1, 'C', True)
        
        pdf.set_font("Arial", "", 11)
        pdf.cell(60, 10, "Threat Type:", 1, 0, 'L', True)
        pdf.cell(130, 10, threat_type, 1, 1, 'L')
        
        pdf.cell(60, 10, "Severity:", 1, 0, 'L', True)
        pdf.cell(130, 10, severity, 1, 1, 'L')
        
        pdf.cell(60, 10, "Confidence Score:", 1, 0, 'L', True)
        pdf.cell(130, 10, f"{confidence_score:.2f}", 1, 1, 'L')
        pdf.ln(5)
        
        # Recommendation section
        pdf.set_font("Arial", "B", 13)
        pdf.cell(0, 10, "Recommended Actions", 0, 1)
        pdf.set_font("Arial", "", 11)
        pdf.multi_cell(0, 6, recommendation)
        pdf.ln(5)
        
        # Try to parse any additional data that might be stored in JSON format
        try:
            additional_data = {}
            if hasattr(scan, 'description') and scan.description:
                additional_data['description'] = clean_text_for_pdf(scan.description)
            if hasattr(scan, 'ioc') and scan.ioc:
                additional_data['ioc'] = clean_text_for_pdf(scan.ioc)
            if hasattr(scan, 'source') and scan.source:
                additional_data['source'] = clean_text_for_pdf(scan.source)
            
            if additional_data:
                pdf.set_font("Arial", "B", 13)
                pdf.cell(0, 10, "Additional Information", 0, 1)
                pdf.set_font("Arial", "", 11)
                
                for key, value in additional_data.items():
                    pdf.set_font("Arial", "B", 11)
                    pdf.cell(0, 6, f"{key.capitalize()}:", 0, 1)
                    pdf.set_font("Arial", "", 11)
                    pdf.multi_cell(0, 6, f"{value}")
                    pdf.ln(3)
                
                pdf.ln(5)
        except Exception as e:
            logging.warning(f"Error parsing additional data: {str(e)}")
        
        # Content sample
        pdf.set_font("Arial", "B", 13)
        pdf.cell(0, 10, "Content Sample", 0, 1)
        pdf.set_font("Arial", "", 10)
        
        # Limit content to avoid too large PDFs
        content_sample = content
        if content_sample:
            if len(content_sample) > 1500:
                content_sample = content_sample[:1500] + "..."
            
            pdf.multi_cell(0, 6, content_sample)
        else:
            pdf.multi_cell(0, 6, "No content available for this scan.")
        
        pdf.ln(5)
        
        # Technical Details section
        pdf.add_page()
        pdf.set_font("Arial", "B", 13)
        pdf.cell(0, 10, "Technical Details", 0, 1)
        pdf.set_font("Arial", "", 11)
        
        # Create a technical explanation based on the threat type
        tech_details = ""
        if threat_type == "Malware":
            tech_details = "Malware encompasses various types of malicious software including viruses, worms, trojans, ransomware, spyware, adware, and other harmful programs. It typically operates by infiltrating systems through deceptive means and executing unauthorized operations."
        elif threat_type == "Phishing":
            tech_details = "Phishing attacks involve fraudulent attempts to obtain sensitive information such as usernames, passwords, and credit card details by disguising as a trustworthy entity. Attackers often use email spoofing and malicious websites that mimic legitimate ones."
        elif threat_type == "Ransomware":
            tech_details = "Ransomware is a type of malware that encrypts files on a victim's computer, making them inaccessible, and demands a ransom payment to restore access. Modern ransomware attacks also often involve threatening to publish the victim's data or permanently block access to it."
        else:
            tech_details = f"This {threat_type} represents a specialized cyber threat that may target specific vulnerabilities or employ unique attack vectors. Such threats often exploit security weaknesses in systems, networks, or human behavior to gain unauthorized access or execute harmful operations."
        
        pdf.multi_cell(0, 6, tech_details)
        pdf.ln(5)
        
        # Risk Mitigation Strategies
        pdf.set_font("Arial", "B", 13)
        pdf.cell(0, 10, "Risk Mitigation Strategies", 0, 1)
        pdf.set_font("Arial", "", 11)
        
        # Generic security recommendations
        pdf.set_font("Arial", "B", 11)
        pdf.cell(0, 8, "General Security Recommendations:", 0, 1)
        pdf.set_font("Arial", "", 11)
        
        security_recs = [
            "Keep all systems and software updated with the latest security patches",
            "Implement multi-factor authentication wherever possible",
            "Use strong, unique passwords for all accounts",
            "Backup critical data regularly using the 3-2-1 backup strategy",
            "Deploy and maintain reputable antivirus and anti-malware solutions",
            "Conduct regular security awareness training for all users",
            "Implement network segmentation to contain potential breaches",
            "Use encryption for sensitive data both in transit and at rest"
        ]
        
        for i, rec in enumerate(security_recs, 1):
            pdf.cell(10, 6, f"{i}.", 0, 0)
            pdf.multi_cell(0, 6, rec)
        
        # Create a temporary file to save the PDF
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
            pdf_path = tmp.name
        
        # Save the PDF to the temporary file
        pdf.output(pdf_path)
        
        return pdf_path
    
    except Exception as e:
        logging.error(f"Error generating PDF report: {str(e)}")
        logging.exception("Exception traceback:")
        # Return a path to an error report if possible
        try:
            error_pdf = ThreatReportPDF()
            error_pdf.add_page()
            error_pdf.set_font("Arial", "B", 15)
            error_pdf.cell(0, 10, "Error Generating Threat Report", 0, 1, 'C')
            error_pdf.set_font("Arial", "", 12)
            error_pdf.cell(0, 10, f"Error: {str(e)}", 0, 1)
            error_pdf.cell(0, 10, "Please contact support for assistance.", 0, 1)
            
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
                error_path = tmp.name
            error_pdf.output(error_path)
            return error_path
        except:
            # If we can't even generate an error PDF, just raise the original exception
            raise

def send_report_email(scan, recipient_email):
    """
    Send a threat report via email.
    
    Args:
        scan: The Scan object containing threat details
        recipient_email: The email address to send the report to
    """
    try:
        # Import the email module
        from utils.email_sender import send_email
        
        # Generate PDF report
        pdf_path = generate_pdf_report(scan)
        
        # Create email message
        subject = f"Threat Report - {scan.threat_type} Detected"
        
        body = f"""
        <html>
        <body>
            <h2>Dark Web Threat Detection Report</h2>
            <p>Hello,</p>
            <p>Please find attached the threat report for your recent scan.</p>
            <p><strong>URL:</strong> {scan.url}</p>
            <p><strong>Threat Type:</strong> {scan.threat_type}</p>
            <p><strong>Severity:</strong> {scan.severity}</p>
            <p><strong>Confidence Score:</strong> {scan.confidence_score:.2f}</p>
            <p><strong>Recommendation:</strong> {scan.recommendation}</p>
            <p>For more details, please refer to the attached PDF report.</p>
            <p>This is an automated email, please do not reply.</p>
            <p>Regards,<br>Dark Web Threat Detector</p>
        </body>
        </html>
        """
        
        # Send the email using smtplib
        success = send_email(
            recipient_email=recipient_email,
            subject=subject,
            html_content=body,
            attachment_path=pdf_path,
            attachment_name=f'threat_report_{scan.id}.pdf'
        )
        
        # Delete the temporary PDF file
        os.unlink(pdf_path)
        
        if not success:
            raise Exception("Failed to send email")
            
    except Exception as e:
        logging.error(f"Error sending report email: {str(e)}")
        raise
