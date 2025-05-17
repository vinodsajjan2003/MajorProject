#!/usr/bin/env python3
"""
Script to run auto scans every 2 minutes.
This script continuously runs and checks for URLs to scan every 2 minutes.
"""
import logging
import sys
import time
from datetime import datetime, timedelta
from app import app, db
from models import AutoScanURL
from utils.auto_scan import process_auto_scan_url

def run_2min_auto_scans():
    """
    Run all active auto-scan URLs with 2-minute frequency that are due for scanning.
    
    Returns:
        int: Number of URLs successfully processed
    """
    with app.app_context():
        now = datetime.utcnow()
        processed_count = 0
        
        # Get only active auto-scan URLs with 2min frequency
        two_min_urls = AutoScanURL.query.filter_by(
            active=True, 
            scan_frequency='2min'
        ).all()
        
        logging.info(f"Found {len(two_min_urls)} active 2-minute interval auto-scan URLs")
        
        for auto_url in two_min_urls:
            should_scan = False
            
            # If never scanned before, scan it now
            if not auto_url.last_scanned_at:
                should_scan = True
                logging.info(f"URL {auto_url.url} has never been scanned before")
            else:
                time_diff = now - auto_url.last_scanned_at
                
                # Scan if more than 2 minutes have passed
                if time_diff.total_seconds() >= 120:  # 2 minutes = 120 seconds
                    should_scan = True
                    logging.info(f"URL {auto_url.url} is due for 2-minute interval scanning")
            
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
        
        logging.info(f"2-minute interval auto-scan completed. Processed {processed_count} URLs.")
        return processed_count

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("2min_auto_scan.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logging.info("Starting 2-minute interval auto-scan service...")
    
    try:
        # Run continuously
        while True:
            try:
                count = run_2min_auto_scans()
                logging.info(f"2-minute scan cycle completed. Processed {count} URLs.")
            except Exception as e:
                logging.error(f"Error during 2-minute scan cycle: {str(e)}")
                
            # Wait for 2 minutes before the next cycle
            logging.info("Waiting for 2 minutes before next scan cycle...")
            time.sleep(120)  # 2 minutes in seconds
            
    except KeyboardInterrupt:
        logging.info("2-minute auto-scan service stopped by user.")
    except Exception as e:
        logging.error(f"Fatal error in 2-minute auto-scan service: {str(e)}")
        sys.exit(1)