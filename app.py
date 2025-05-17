import os
import logging
from datetime import datetime
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_login import LoginManager
from flask_mail import Mail

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Set up SQLAlchemy base class
class Base(DeclarativeBase):
    pass

# Initialize extensions
db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()
mail = Mail()

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the app
app.config.from_object('config.Config')

# Create a new database URL from the individual environment variables
# if they are available
if (os.environ.get('PGUSER') and os.environ.get('PGPASSWORD') and 
    os.environ.get('PGHOST') and os.environ.get('PGDATABASE')):
    user = os.environ.get('PGUSER')
    password = os.environ.get('PGPASSWORD')
    host = os.environ.get('PGHOST')
    database = os.environ.get('PGDATABASE')
    port = os.environ.get('PGPORT', '5432')
    
    db_url = f"postgresql://{user}:{password}@{host}:{port}/{database}?sslmode=require"
    logging.info(f"Constructed database URL from environment variables")
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
elif os.environ.get('DATABASE_URL'):
    # Fallback to DATABASE_URL if individual variables are not available
    db_url = os.environ.get('DATABASE_URL')
    logging.info(f"Using database URL from environment")
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
else:
    # Use SQLite as fallback for local development
    sqlite_path = 'dark_web_threat_detector.db'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{sqlite_path}'
    logging.warning(f"No database connection information found in environment variables! Using SQLite at {sqlite_path}")
    
# Additional database connection options to help with reconnection
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,
    "pool_recycle": 300
}

# Only add connect_timeout for PostgreSQL (not SQLite)
if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI']:
    app.config['SQLALCHEMY_ENGINE_OPTIONS']["connect_args"] = {
        "connect_timeout": 10
    }

# Add utility functions to Jinja2 templates
app.jinja_env.globals['now'] = datetime.utcnow

# Initialize extensions with app
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'
mail.init_app(app)

try:
    with app.app_context():
        # Import routes and models
        from routes import *
        import models

        # Try to create database tables, but continue even if it fails
        try:
            db.create_all()
            logging.info("Database tables created successfully")
        except Exception as e:
            logging.error(f"Error creating database tables: {str(e)}")
            logging.warning("Continuing without database support - some features will be limited")
        
        # Create model directory if it doesn't exist
        os.makedirs('models', exist_ok=True)
        
        # Start the background auto-scan thread
        try:
            from auto_scan_background import start_background_thread
            start_background_thread()
            logging.info("Auto-scan background thread started successfully")
        except Exception as e:
            logging.error(f"Error starting auto-scan background thread: {str(e)}")
            logging.warning("Auto-scan functionality may not work automatically")
except Exception as e:
    logging.error(f"Application initialization error: {str(e)}")
    logging.warning("Application may have limited functionality")
