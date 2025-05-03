import os
import tempfile
from fpdf import FPDF
from datetime import datetime
from flask_mail import Message
from app import app, mail
import logging

def generate_pdf_report(scan):
    """
    Generate a PDF report for a scan.
    
    Args:
        scan: The Scan object containing threat details
    
    Returns:
        str: Path to the generated PDF file
    """
    try:
        # Create a PDF object
        pdf = FPDF()
        pdf.add_page()
        
        # Set up fonts
        pdf.set_font("Arial", "B", 16)
        
        # Title
        pdf.cell(0, 10, "Dark Web Threat Detection Report", 0, 1, "C")
        pdf.ln(10)
        
        # Date and time
        pdf.set_font("Arial", "I", 10)
        pdf.cell(0, 6, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, "R")
        pdf.ln(5)
        
        # Set normal font for content
        pdf.set_font("Arial", "", 11)
        
        # URL information
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "URL Information", 0, 1)
        pdf.set_font("Arial", "", 11)
        pdf.multi_cell(0, 6, f"Scanned URL: {scan.url}")
        pdf.multi_cell(0, 6, f"Scan Date: {scan.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        pdf.ln(5)
        
        # Threat details
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Threat Analysis", 0, 1)
        pdf.set_font("Arial", "", 11)
        pdf.multi_cell(0, 6, f"Threat Type: {scan.threat_type}")
        pdf.multi_cell(0, 6, f"Severity: {scan.severity}")
        pdf.multi_cell(0, 6, f"Confidence Score: {scan.confidence_score:.2f}")
        pdf.ln(5)
        
        # Recommendation
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Recommendation", 0, 1)
        pdf.set_font("Arial", "", 11)
        pdf.multi_cell(0, 6, f"{scan.recommendation}")
        pdf.ln(5)
        
        # Content sample
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Content Sample", 0, 1)
        pdf.set_font("Arial", "", 10)
        
        # Limit content to avoid too large PDFs
        content_sample = scan.content
        if len(content_sample) > 1000:
            content_sample = content_sample[:1000] + "..."
        
        pdf.multi_cell(0, 6, f"{content_sample}")
        pdf.ln(5)
        
        # Footer
        pdf.set_y(-30)
        pdf.set_font("Arial", "I", 8)
        pdf.cell(0, 10, "This report is generated automatically by Dark Web Threat Detector.", 0, 1, "C")
        pdf.cell(0, 10, "CONFIDENTIAL - FOR AUTHORIZED USE ONLY", 0, 1, "C")
        
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
