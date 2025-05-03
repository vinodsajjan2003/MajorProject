"""
Automated URL scanning utility for processing URLs saved in the database.
"""
import logging
from datetime import datetime
from app import app, db
from models import User, Scan, AutoScanURL
from utils.scraper import scrape_url_content
from utils.distilbert_model import detect_threat, get_threat_details
from utils.report import generate_pdf_report, send_report_email

def process_auto_scan_url(auto_scan_url):
    """
    Process a single auto-scan URL entry.
    
    Args:
        auto_scan_url: AutoScanURL object to process
    
    Returns:
        Scan: The created scan object
    """
    try:
        logging.info(f"Processing auto-scan URL: {auto_scan_url.url}")
        
        # Scrape content from the URL
        content = scrape_url_content(auto_scan_url.url)
        
        if not content:
            logging.error(f"Failed to retrieve content from URL: {auto_scan_url.url}")
            return None
        
        # Detect threat using the DistilBERT model
        threat_type = detect_threat(content)
        
        # Get threat details
        threat_details = get_threat_details(threat_type)
        
        # Create new scan record
        scan = Scan(
            url=auto_scan_url.url,
            content=content,
            threat_type=threat_type,
            severity=threat_details.get('severity'),
            confidence_score=threat_details.get('confidence_score'),
            recommendation=threat_details.get('recommendation'),
            description=threat_details.get('description'),
            ioc=threat_details.get('ioc'),
            source=threat_details.get('source'),
            user_id=auto_scan_url.user_id,
            auto_scan_url_id=auto_scan_url.id
        )
        
        # Save scan to database
        db.session.add(scan)
        
        # Update auto-scan URL's last scanned timestamp
        auto_scan_url.last_scanned_at = datetime.utcnow()
        
        db.session.commit()
        
        # Send email notification if enabled
        if auto_scan_url.email_notification and auto_scan_url.notification_email:
            try:
                # Use the notification email from the auto_scan_url
                send_report_email(scan, auto_scan_url.notification_email)
                logging.info(f"Email report sent to {auto_scan_url.notification_email}")
            except Exception as e:
                logging.error(f"Failed to send email notification: {str(e)}")
        
        return scan
        
    except Exception as e:
        logging.error(f"Error processing auto-scan URL {auto_scan_url.url}: {str(e)}")
        db.session.rollback()
        return None

def run_all_auto_scans():
    """
    Run all active auto-scan URLs that are due for scanning.
    
    Returns:
        int: Number of URLs successfully processed
    """
    with app.app_context():
        # Get all active auto-scan URLs
        auto_scan_urls = AutoScanURL.query.filter_by(active=True).all()
        
        logging.info(f"Found {len(auto_scan_urls)} active auto-scan URLs")
        
        processed_count = 0
        for auto_url in auto_scan_urls:
            scan = process_auto_scan_url(auto_url)
            if scan:
                processed_count += 1
        
        logging.info(f"Successfully processed {processed_count} auto-scan URLs")
        return processed_count

def run_auto_scan_for_user(user_id):
    """
    Run all active auto-scan URLs for a specific user.
    
    Args:
        user_id: ID of the user
        
    Returns:
        int: Number of URLs successfully processed
    """
    with app.app_context():
        # Get all active auto-scan URLs for the user
        auto_scan_urls = AutoScanURL.query.filter_by(user_id=user_id, active=True).all()
        
        logging.info(f"Found {len(auto_scan_urls)} active auto-scan URLs for user {user_id}")
        
        processed_count = 0
        for auto_url in auto_scan_urls:
            scan = process_auto_scan_url(auto_url)
            if scan:
                processed_count += 1
        
        logging.info(f"Successfully processed {processed_count} auto-scan URLs for user {user_id}")
        return processed_count

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_all_auto_scans()