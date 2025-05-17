#!/usr/bin/env python3
"""
Script to run hourly automated URL scans.
This script is designed to be executed every hour via cron.
"""
import logging
import sys
from datetime import datetime
from app import app, db
from models import AutoScanURL
from utils.auto_scan import process_auto_scan_url

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("hourly_auto_scan.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    try:
        with app.app_context():
            now = datetime.utcnow()
            processed_count = 0
            
            # Get only active auto-scan URLs with hourly frequency
            hourly_urls = AutoScanURL.query.filter_by(
                active=True, 
                scan_frequency='hourly'
            ).all()
            
            logging.info(f"Found {len(hourly_urls)} active hourly auto-scan URLs")
            
            for auto_url in hourly_urls:
                should_scan = False
                
                # If never scanned before, scan it now
                if not auto_url.last_scanned_at:
                    should_scan = True
                    logging.info(f"URL {auto_url.url} has never been scanned before")
                else:
                    time_diff = now - auto_url.last_scanned_at
                    
                    # Scan if more than 1 hour has passed
                    if time_diff.total_seconds() >= 3600:  # 1 hour = 3600 seconds
                        should_scan = True
                        logging.info(f"URL {auto_url.url} is due for hourly scanning")
                
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
            
            logging.info(f"Hourly auto-scan completed. Processed {processed_count} URLs.")
            
    except Exception as e:
        logging.error(f"Error during hourly auto-scan: {str(e)}")
        sys.exit(1)