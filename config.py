import os

class Config:
    # Flask configuration
    DEBUG = True
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///dark_web_threat_detector.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }
    
    # Mail configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('vinodsajjan2003@gmail.com')
    MAIL_PASSWORD = os.environ.get('vwzhjfkbquabfkin')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')
    
    # Model paths
    MODEL_DIR = 'models'
    MODEL_PATH = os.path.join(MODEL_DIR, 'threat_model.joblib')
    CATEGORIES_PATH = os.path.join(MODEL_DIR, 'threat_categories.joblib')
    
    # Tor proxy configuration
    TOR_PROXY_HOST = os.environ.get('TOR_PROXY_HOST', '127.0.0.1')
    TOR_PROXY_PORT = int(os.environ.get('TOR_PROXY_PORT', 9050))
    
    # Dataset path
    DATASET_PATH = 'data/synthetic_cyber_threats_100k.csv'
    
    # User requests throttling
    MAX_SCANS_PER_HOUR = 10
