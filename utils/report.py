import os
import tempfile
from fpdf import FPDF
from datetime import datetime
from flask_mail import Message
from app import app, mail
import logging
import json

class ThreatReportPDF(FPDF):
    """Custom PDF class for threat reports with headers and footers"""
    
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
        
        # Create summary based on threat type and severity
        summary = f"Analysis of the URL {scan.url} has identified it as a potential source of {scan.threat_type.lower()} threats. "
        
        if scan.severity == "High":
            summary += f"This threat is classified as HIGH severity with a confidence score of {scan.confidence_score:.2f}, indicating an immediate risk that requires prompt action."
        elif scan.severity == "Medium":
            summary += f"This threat is classified as MEDIUM severity with a confidence score of {scan.confidence_score:.2f}, suggesting moderate risk that should be addressed."
        else:
            summary += f"This threat is classified as LOW severity with a confidence score of {scan.confidence_score:.2f}, indicating minimal immediate risk but should still be monitored."
        
        pdf.multi_cell(0, 6, summary)
        pdf.ln(5)
        
        # URL information section
        pdf.set_font("Arial", "B", 13)
        pdf.cell(0, 10, "URL Information", 0, 1)
        pdf.set_font("Arial", "", 11)
        
        # URL details table
        pdf.set_fill_color(240, 240, 240)  # Light gray background
        pdf.cell(40, 10, "URL:", 1, 0, 'L', 1)
        pdf.cell(150, 10, scan.url, 1, 1, 'L')
        pdf.cell(40, 10, "Scan Date:", 1, 0, 'L', 1)
        pdf.cell(150, 10, scan.created_at.strftime('%Y-%m-%d %H:%M:%S'), 1, 1, 'L')
        pdf.ln(5)
        
        # Threat Analysis section
        pdf.set_font("Arial", "B", 13)
        pdf.cell(0, 10, "Threat Analysis", 0, 1)
        
        # Create a colored box based on severity
        if scan.severity == "High":
            pdf.set_fill_color(255, 200, 200)  # Light red
        elif scan.severity == "Medium":
            pdf.set_fill_color(255, 235, 175)  # Light orange/yellow
        else:
            pdf.set_fill_color(200, 255, 200)  # Light green
            
        # Create a table for threat details
        pdf.set_font("Arial", "B", 11)
        pdf.cell(190, 10, "Threat Details", 1, 1, 'C', 1)
        
        pdf.set_font("Arial", "", 11)
        pdf.cell(60, 10, "Threat Type:", 1, 0, 'L', 1)
        pdf.cell(130, 10, scan.threat_type, 1, 1, 'L')
        
        pdf.cell(60, 10, "Severity:", 1, 0, 'L', 1)
        pdf.cell(130, 10, scan.severity, 1, 1, 'L')
        
        pdf.cell(60, 10, "Confidence Score:", 1, 0, 'L', 1)
        pdf.cell(130, 10, f"{scan.confidence_score:.2f}", 1, 1, 'L')
        pdf.ln(5)
        
        # Recommendation section
        pdf.set_font("Arial", "B", 13)
        pdf.cell(0, 10, "Recommended Actions", 0, 1)
        pdf.set_font("Arial", "", 11)
        pdf.multi_cell(0, 6, scan.recommendation)
        pdf.ln(5)
        
        # Try to parse any additional data that might be stored in JSON format
        try:
            additional_data = {}
            if hasattr(scan, 'description') and scan.description:
                additional_data['description'] = scan.description
            if hasattr(scan, 'ioc') and scan.ioc:
                additional_data['ioc'] = scan.ioc
            if hasattr(scan, 'source') and scan.source:
                additional_data['source'] = scan.source
            
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
        content_sample = scan.content
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
        if scan.threat_type == "Malware":
            tech_details = "Malware encompasses various types of malicious software including viruses, worms, trojans, ransomware, spyware, adware, and other harmful programs. It typically operates by infiltrating systems through deceptive means and executing unauthorized operations."
        elif scan.threat_type == "Phishing":
            tech_details = "Phishing attacks involve fraudulent attempts to obtain sensitive information such as usernames, passwords, and credit card details by disguising as a trustworthy entity. Attackers often use email spoofing and malicious websites that mimic legitimate ones."
        elif scan.threat_type == "Ransomware":
            tech_details = "Ransomware is a type of malware that encrypts files on a victim's computer, making them inaccessible, and demands a ransom payment to restore access. Modern ransomware attacks also often involve threatening to publish the victim's data or permanently block access to it."
        else:
            tech_details = f"This {scan.threat_type} represents a specialized cyber threat that may target specific vulnerabilities or employ unique attack vectors. Such threats often exploit security weaknesses in systems, networks, or human behavior to gain unauthorized access or execute harmful operations."
        
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
        raise

def send_report_email(scan, recipient_email):
    """
    Send a threat report via email.
    
    Args:
        scan: The Scan object containing threat details
        recipient_email: The email address to send the report to
    """
    try:
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
        
        msg = Message(
            subject=subject,
            recipients=[recipient_email],
            html=body
        )
        
        # Attach the PDF report
        with open(pdf_path, 'rb') as f:
            msg.attach(
                filename=f'threat_report_{scan.id}.pdf',
                content_type='application/pdf',
                data=f.read()
            )
        
        # Send the email
        mail.send(msg)
        
        # Delete the temporary PDF file
        os.unlink(pdf_path)
        
    except Exception as e:
        logging.error(f"Error sending email report: {str(e)}")
        raise
