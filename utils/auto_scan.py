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
        url = auto_scan_url.url
        logging.info(f"Processing auto-scan URL: {url}")
        
        # Check if it's a Tor hidden service (.onion domain)
        from utils.scraper import is_onion_url
        is_onion = is_onion_url(url)
        
        # Scrape content from the URL with our improved scraper
        content = scrape_url_content(url)
        
        # If content is empty, log and return
        if not content:
            logging.error(f"Failed to retrieve content from URL: {url}")
            return None
        
        # Detect threat using the DistilBERT model
        threat_type = detect_threat(content)
        
        # Get threat details from the dataset
        threat_details = get_threat_details(threat_type)
        
        # For onion URLs, add specialized threat details based on URL and content
        if is_onion:
            # Determine the type of dark web content
            url_lower = url.lower()
            
            if 'market' in url_lower or 'shop' in url_lower or 'store' in url_lower:
                dark_web_type = 'Dark Web Marketplace'
                severity = 'High'
                description = "Dark web marketplace potentially offering illegal goods or services."
                recommendation = (
                    "This appears to be a dark web marketplace. Such sites typically involve "
                    "illegal transactions and extreme caution is advised. Never provide personal "
                    "information or engage in any transactions on dark web sites."
                )
            elif 'hack' in url_lower or 'exploit' in url_lower or 'forum' in url_lower:
                dark_web_type = 'Dark Web Hacking Forum'
                severity = 'Medium-High'
                description = "Dark web forum discussing hacking, exploits, or other potentially illegal activities."
                recommendation = (
                    "This appears to be a dark web forum related to hacking or exploits. "
                    "Such forums often contain discussions of illegal activities and may "
                    "expose visitors to malware or other security threats."
                )
            else:
                dark_web_type = 'Dark Web Services'
                severity = 'Medium'
                description = "Unidentified dark web service that requires Tor Browser to access."
                recommendation = (
                    "This appears to be a dark web service site. Exercise extreme caution "
                    "with dark web content as it often contains illegal services. "
                    "Never provide personal information or credentials on dark web sites."
                )
            
            # Use our enhanced classification regardless of the model result
            threat_type = dark_web_type
            
            # Set enhanced threat details
            threat_details['severity'] = severity
            threat_details['description'] = description
            threat_details['recommendation'] = recommendation
            
            # Set IoC to the onion domain itself
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            threat_details['ioc'] = parsed_url.netloc
            threat_details['source'] = "Dark Web Classification System"
            
            # Set a reasonable confidence score
            threat_details['confidence_score'] = 0.90
                
            logging.info(f"Processed .onion URL with threat type: {threat_type}")
        
        # Create new scan record
        scan = Scan(
            url=url,
            content=content[:10000],  # Limit content length for database storage
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
    Run all active auto-scan URLs that are due for scanning based on their frequency.
    
    Returns:
        int: Number of URLs successfully processed
    """
    with app.app_context():
        now = datetime.utcnow()
        processed_count = 0
        
        # Get all active auto-scan URLs
        auto_scan_urls = AutoScanURL.query.filter_by(active=True).all()
        
        logging.info(f"Found {len(auto_scan_urls)} active auto-scan URLs")
        
        for auto_url in auto_scan_urls:
            # Check if the URL is due for scanning based on frequency
            should_scan = False
            
            # If never scanned before, scan it now
            if not auto_url.last_scanned_at:
                should_scan = True
                logging.info(f"URL {auto_url.url} has never been scanned before")
            else:
                time_diff = now - auto_url.last_scanned_at
                
                # Check frequency
                if auto_url.scan_frequency == 'hourly':
                    # Scan if more than 1 hour has passed
                    if time_diff.total_seconds() >= 3600:  # 1 hour = 3600 seconds
                        should_scan = True
                        logging.info(f"URL {auto_url.url} is due for hourly scanning")
                elif auto_url.scan_frequency == 'daily':
                    # Scan if more than 24 hours have passed
                    if time_diff.total_seconds() >= 86400:  # 24 hours = 86400 seconds
                        should_scan = True
                        logging.info(f"URL {auto_url.url} is due for daily scanning")
                elif auto_url.scan_frequency == 'weekly':
                    # Scan if more than 7 days have passed
                    if time_diff.total_seconds() >= 604800:  # 7 days = 604800 seconds
                        should_scan = True
                        logging.info(f"URL {auto_url.url} is due for weekly scanning")
                elif auto_url.scan_frequency == 'monthly':
                    # Scan if more than 30 days have passed
                    if time_diff.total_seconds() >= 2592000:  # 30 days = 2592000 seconds
                        should_scan = True
                        logging.info(f"URL {auto_url.url} is due for monthly scanning")
            
            # Process URL if it's due for scanning
            if should_scan:
                scan = process_auto_scan_url(auto_url)
                if scan:
                    processed_count += 1
                    logging.info(f"Successfully processed URL: {auto_url.url}")
                else:
                    logging.error(f"Failed to process URL: {auto_url.url}")
            else:
                logging.info(f"URL {auto_url.url} is not due for scanning yet")
        
        logging.info(f"Successfully processed {processed_count} auto-scan URLs")
        return processed_count

def run_auto_scan_for_user(user_id):
    """
    Run all active auto-scan URLs for a specific user that are due based on frequency.
    
    Args:
        user_id: ID of the user
        
    Returns:
        int: Number of URLs successfully processed
    """
    with app.app_context():
        now = datetime.utcnow()
        processed_count = 0
        
        # Get all active auto-scan URLs for the user
        auto_scan_urls = AutoScanURL.query.filter_by(user_id=user_id, active=True).all()
        
        logging.info(f"Found {len(auto_scan_urls)} active auto-scan URLs for user {user_id}")
        
        for auto_url in auto_scan_urls:
            # Check if the URL is due for scanning based on frequency
            should_scan = False
            
            # If never scanned before, scan it now
            if not auto_url.last_scanned_at:
                should_scan = True
                logging.info(f"URL {auto_url.url} has never been scanned before")
            else:
                time_diff = now - auto_url.last_scanned_at
                
                # Check frequency
                if auto_url.scan_frequency == 'hourly':
                    # Scan if more than 1 hour has passed
                    if time_diff.total_seconds() >= 3600:  # 1 hour = 3600 seconds
                        should_scan = True
                        logging.info(f"URL {auto_url.url} is due for hourly scanning")
                elif auto_url.scan_frequency == 'daily':
                    # Scan if more than 24 hours have passed
                    if time_diff.total_seconds() >= 86400:  # 24 hours = 86400 seconds
                        should_scan = True
                        logging.info(f"URL {auto_url.url} is due for daily scanning")
                elif auto_url.scan_frequency == 'weekly':
                    # Scan if more than 7 days have passed
                    if time_diff.total_seconds() >= 604800:  # 7 days = 604800 seconds
                        should_scan = True
                        logging.info(f"URL {auto_url.url} is due for weekly scanning")
                elif auto_url.scan_frequency == 'monthly':
                    # Scan if more than 30 days have passed
                    if time_diff.total_seconds() >= 2592000:  # 30 days = 2592000 seconds
                        should_scan = True
                        logging.info(f"URL {auto_url.url} is due for monthly scanning")
            
            # Process URL if it's due for scanning
            if should_scan:
                scan = process_auto_scan_url(auto_url)
                if scan:
                    processed_count += 1
                    logging.info(f"Successfully processed URL: {auto_url.url} for user {user_id}")
                else:
                    logging.error(f"Failed to process URL: {auto_url.url} for user {user_id}")
            else:
                logging.info(f"URL {auto_url.url} for user {user_id} is not due for scanning yet")
        
        logging.info(f"Successfully processed {processed_count} auto-scan URLs for user {user_id}")
        return processed_count

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_all_auto_scans()