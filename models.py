from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship('Scan', backref='user', lazy=True)
    auto_scan_urls = db.relationship('AutoScanURL', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(512), nullable=False)
    content = db.Column(db.Text)
    threat_type = db.Column(db.String(64))
    severity = db.Column(db.String(32))
    confidence_score = db.Column(db.Float)
    recommendation = db.Column(db.Text)
    
    # Additional fields from synthetic dataset
    description = db.Column(db.Text)
    ioc = db.Column(db.String(255))  # Indicator of Compromise (e.g., IP, domain, file hash)
    source = db.Column(db.String(128))  # Source of threat information
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Link to auto-scan if this scan was generated automatically
    auto_scan_url_id = db.Column(db.Integer, db.ForeignKey('auto_scan_url.id'), nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'content': self.content[:500] + '...' if self.content and len(self.content) > 500 else self.content,
            'threat_type': self.threat_type,
            'severity': self.severity,
            'confidence_score': self.confidence_score,
            'recommendation': self.recommendation,
            'description': self.description,
            'ioc': self.ioc,
            'source': self.source,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'user_id': self.user_id,
            'auto_scan_url_id': self.auto_scan_url_id
        }

class AutoScanURL(db.Model):
    """URLs that should be automatically scanned on a schedule"""
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(512), nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    # Notification settings
    email_notification = db.Column(db.Boolean, default=True)
    notification_email = db.Column(db.String(120), nullable=True)
    
    # Schedule settings (for future implementation)
    scan_frequency = db.Column(db.String(20), default='daily')  # daily, weekly, monthly
    
    # Tracking
    last_scanned_at = db.Column(db.DateTime, nullable=True)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationship with scan results
    scans = db.relationship('Scan', backref='auto_scan_url', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'description': self.description,
            'email_notification': self.email_notification,
            'notification_email': self.notification_email,
            'scan_frequency': self.scan_frequency,
            'last_scanned_at': self.last_scanned_at.strftime('%Y-%m-%d %H:%M:%S') if self.last_scanned_at else None,
            'active': self.active,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'user_id': self.user_id
        }
