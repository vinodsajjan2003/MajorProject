import os
import sys
import logging

# Try to import local configuration if running locally
try:
    import local_config
    logging.info("Loaded local configuration for development environment")
except ImportError:
    logging.info("No local configuration found, using environment variables")

from app import app

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
