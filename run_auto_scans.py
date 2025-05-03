"""
Script to run all automated URL scans.
This can be executed manually or scheduled via cron.
"""
import logging
import sys
from utils.auto_scan import run_all_auto_scans

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("auto_scan.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    try:
        count = run_all_auto_scans()
        logging.info(f"Auto-scan completed successfully. Processed {count} URLs.")
    except Exception as e:
        logging.error(f"Error during auto-scan: {str(e)}")
        sys.exit(1)