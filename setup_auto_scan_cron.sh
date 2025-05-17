#!/bin/bash

# This script sets up cron jobs for auto-scanning URLs at different frequencies
# Must be run as a user with crontab access

# Get the absolute path to the application directory
APP_DIR=$(pwd)

# Create a temporary crontab file
TEMP_CRONTAB=$(mktemp)

# Dump the current crontab to the temporary file
crontab -l > $TEMP_CRONTAB 2>/dev/null

# Add cron job for hourly scans
echo "# Dark Web Threat Detector - Hourly URL scans" >> $TEMP_CRONTAB
echo "0 * * * * cd $APP_DIR && python3 run_hourly_auto_scans.py >> hourly_scan.log 2>&1" >> $TEMP_CRONTAB

# Add cron job for daily scans
echo "# Dark Web Threat Detector - Daily URL scans" >> $TEMP_CRONTAB
echo "0 0 * * * cd $APP_DIR && python3 run_auto_scans.py >> daily_scan.log 2>&1" >> $TEMP_CRONTAB

# Install the updated crontab
crontab $TEMP_CRONTAB

# Clean up the temporary file
rm $TEMP_CRONTAB

echo "Cron jobs for auto URL scanning have been set up:"
echo "- Hourly scans: Every hour at minute 0"
echo "- Daily scans: Every day at midnight"
echo ""
echo "To view your crontab, run: crontab -l"
echo "To edit your crontab manually, run: crontab -e"