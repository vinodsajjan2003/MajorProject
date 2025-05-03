import os
import sys
import requests
import logging
from datetime import datetime

def send_email_with_sendgrid(recipient_email, subject, html_content, attachment_path=None, attachment_name=None):
    """
    Send an email using the SendGrid API directly.
    
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
        sendgrid_api_key = os.environ.get('SENDGRID_API_KEY')
        if not sendgrid_api_key:
            logging.error("SENDGRID_API_KEY not found in environment variables")
            return False
            
        # Set up the API endpoint and headers
        url = "https://api.sendgrid.com/v3/mail/send"
        headers = {
            "Authorization": f"Bearer {sendgrid_api_key}",
            "Content-Type": "application/json"
        }
        
        # Default sender email
        from_email = "threetshieldscan@example.com"
        
        # Create email data
        data = {
            "personalizations": [
                {
                    "to": [{"email": recipient_email}],
                    "subject": subject
                }
            ],
            "from": {"email": from_email, "name": "ThreatShield Scanner"},
            "content": [
                {
                    "type": "text/html",
                    "value": html_content
                }
            ]
        }
        
        # Add attachment if provided
        if attachment_path and attachment_name:
            import base64
            with open(attachment_path, "rb") as f:
                attachment_content = f.read()
                
            encoded_content = base64.b64encode(attachment_content).decode()
            
            data["attachments"] = [
                {
                    "content": encoded_content,
                    "filename": attachment_name,
                    "type": "application/pdf",
                    "disposition": "attachment"
                }
            ]
        
        # Send the request
        response = requests.post(url, headers=headers, json=data)
        
        # Check for success
        if response.status_code >= 200 and response.status_code < 300:
            logging.info(f"Email sent successfully to {recipient_email}")
            return True
        else:
            logging.error(f"Failed to send email: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logging.error(f"Error sending email with SendGrid: {str(e)}")
        return False