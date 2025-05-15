import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

# Email settings
EMAIL_ADDRESS = 'vinodsajjan2003@gmail.com'
EMAIL_PASSWORD = 'axpyjrulnqjbpxfg'
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587

def send_email(recipient_email, subject, html_content, attachment_path=None, attachment_name=None):
    """
    Send an email using the standard smtplib library.
    
    Args:
        recipient_email: Email address of the recipient
        subject: Subject of the email
        html_content: HTML content of the email
        attachment_path: Optional path to a file to attach
        attachment_name: Optional name for the attachment
        
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    try:
        # Create the email message
        message = MIMEMultipart()
        message['From'] = EMAIL_ADDRESS
        message['To'] = recipient_email
        message['Subject'] = subject
        
        # Attach HTML content
        message.attach(MIMEText(html_content, 'html'))
        
        # Attach file if provided
        if attachment_path and attachment_name:
            with open(attachment_path, 'rb') as file:
                attachment = MIMEApplication(file.read(), _subtype="pdf")
                attachment.add_header('Content-Disposition', 'attachment', filename=attachment_name)
                message.attach(attachment)
        
        # Connect to SMTP server and send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Enable TLS encryption
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(message)
            
        logging.info(f"Email sent successfully to {recipient_email}")
        return True
        
    except Exception as e:
        logging.error(f"Error sending email: {str(e)}")
        return False