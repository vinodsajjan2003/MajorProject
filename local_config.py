"""
Local configuration file for development and local running of the application.
Copy this file to your local environment and update the SENDGRID_API_KEY value.
"""
import os

# SendGrid API Key - Replace with your actual key value
os.environ['SENDGRID_API_KEY'] = 'YOUR_SENDGRID_API_KEY_HERE'

# Default sender email
SENDER_EMAIL = 'vinodsajjan2003@gmail.com'

# Database configuration
# If running locally without PostgreSQL, you can use SQLite
# os.environ['DATABASE_URL'] = 'sqlite:///dark_web_threat_detector.db'

# If you have PostgreSQL installed locally, uncomment and configure the following:
# os.environ['DATABASE_URL'] = 'postgresql://username:password@localhost:5432/dark_web_threat_detector'