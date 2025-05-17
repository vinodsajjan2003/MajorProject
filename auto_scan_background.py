"""
Background auto-scanning thread for Dark Web Threat Detector.
This module runs as a background thread inside the main application
to automatically scan URLs based on their configured frequencies.
"""
import logging
import time
import threading
from datetime import datetime, timedelta
from app import app, db
from models import AutoScanURL
from utils.auto_scan import process_auto_scan_url

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global thread object
background_thread = None
should_run = True

def scan_urls_by_frequency(frequency):
    """
    Scan URLs with the specified frequency if they're due
    
    Args:
        frequency (str): The frequency to filter by ('2min', 'hourly', etc.)
        
    Returns:
        int: Number of URLs processed
    """
    try:
        with app.app_context():
            # Check if database is accessible (needed for local development)
            try:
                # Try a simple query to test database connection
                from sqlalchemy import text
                db.session.execute(text("SELECT 1")).fetchone()
            except Exception as db_error:
                # Database is not accessible, log and return
                logger.warning(f"Database not accessible for {frequency} scans: {str(db_error)}")
                return 0
            
            now = datetime.utcnow()
            processed_count = 0
            
            # Get active auto-scan URLs with the specified frequency
            auto_scan_urls = AutoScanURL.query.filter_by(
                active=True, 
                scan_frequency=frequency
            ).all()
            
            logger.info(f"Found {len(auto_scan_urls)} active {frequency} auto-scan URLs")
            
            for auto_url in auto_scan_urls:
                should_scan = False
                
                # If never scanned before, scan it now
                if not auto_url.last_scanned_at:
                    should_scan = True
                    logger.info(f"URL {auto_url.url} has never been scanned before")
                else:
                    time_diff = now - auto_url.last_scanned_at
                    
                    # Check frequency and time threshold
                    if frequency == '2min' and time_diff.total_seconds() >= 120:
                        should_scan = True
                    elif frequency == 'hourly' and time_diff.total_seconds() >= 3600:
                        should_scan = True
                    elif frequency == 'daily' and time_diff.total_seconds() >= 86400:
                        should_scan = True
                    elif frequency == 'weekly' and time_diff.total_seconds() >= 604800:
                        should_scan = True
                    elif frequency == 'monthly' and time_diff.total_seconds() >= 2592000:
                        should_scan = True
                
                # Process URL if it's due for scanning
                if should_scan:
                    try:
                        scan = process_auto_scan_url(auto_url)
                        if scan:
                            processed_count += 1
                            logger.info(f"Successfully processed {frequency} URL: {auto_url.url}")
                        else:
                            logger.error(f"Failed to process {frequency} URL: {auto_url.url}")
                    except Exception as e:
                        logger.error(f"Error processing {frequency} URL {auto_url.url}: {str(e)}")
            
            return processed_count
    except Exception as e:
        logger.error(f"Error processing {frequency} auto-scans: {str(e)}")
        return 0

def auto_scan_thread_function():
    """Main function for the background auto-scan thread"""
    global should_run
    
    # Track when we last ran each frequency
    last_run = {
        '2min': datetime.utcnow() - timedelta(seconds=120),
        'hourly': datetime.utcnow() - timedelta(seconds=3600),
        'daily': datetime.utcnow() - timedelta(seconds=86400),
        'weekly': datetime.utcnow() - timedelta(seconds=604800),
        'monthly': datetime.utcnow() - timedelta(seconds=2592000)
    }
    
    logger.info("Background auto-scan thread started")
    
    while should_run:
        try:
            now = datetime.utcnow()
            
            # Check for 2-minute scans
            if (now - last_run['2min']).total_seconds() >= 120:
                logger.info("Running 2-minute auto-scans")
                count = scan_urls_by_frequency('2min')
                logger.info(f"Processed {count} 2-minute auto-scan URLs")
                last_run['2min'] = now
            
            # Check for hourly scans
            if (now - last_run['hourly']).total_seconds() >= 3600:
                logger.info("Running hourly auto-scans")
                count = scan_urls_by_frequency('hourly')
                logger.info(f"Processed {count} hourly auto-scan URLs")
                last_run['hourly'] = now
            
            # Check for daily scans
            if (now - last_run['daily']).total_seconds() >= 86400:
                logger.info("Running daily auto-scans")
                count = scan_urls_by_frequency('daily')
                logger.info(f"Processed {count} daily auto-scan URLs")
                last_run['daily'] = now
            
            # Check for weekly scans
            if (now - last_run['weekly']).total_seconds() >= 604800:
                logger.info("Running weekly auto-scans")
                count = scan_urls_by_frequency('weekly')
                logger.info(f"Processed {count} weekly auto-scan URLs")
                last_run['weekly'] = now
            
            # Check for monthly scans
            if (now - last_run['monthly']).total_seconds() >= 2592000:
                logger.info("Running monthly auto-scans")
                count = scan_urls_by_frequency('monthly')
                logger.info(f"Processed {count} monthly auto-scan URLs")
                last_run['monthly'] = now
            
            # Sleep for 30 seconds before checking again
            # This is a good balance between responsiveness and CPU usage
            time.sleep(30)
            
        except Exception as e:
            logger.error(f"Error in auto-scan thread: {str(e)}")
            time.sleep(60)  # Sleep longer if there's an error

def start_background_thread():
    """Start the background thread for auto-scanning"""
    global background_thread, should_run
    
    # Only start if not already running
    if background_thread is None or not background_thread.is_alive():
        should_run = True
        background_thread = threading.Thread(target=auto_scan_thread_function)
        background_thread.daemon = True  # This ensures the thread will exit when the main app exits
        background_thread.start()
        logger.info("Started background auto-scan thread")
        return True
    else:
        logger.info("Background auto-scan thread already running")
        return False

def stop_background_thread():
    """Stop the background thread for auto-scanning"""
    global should_run
    should_run = False
    logger.info("Stopping background auto-scan thread")