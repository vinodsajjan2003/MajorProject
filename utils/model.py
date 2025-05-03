import os
import logging
import random
from app import app
import pandas as pd

# Global variables to hold the model, tokenizer, and label mapping
synthetic_data = None

def load_model():
    """Load synthetic data for threat analysis"""
    global synthetic_data
    
    try:
        # Load synthetic data if available
        if os.path.exists(app.config['DATASET_PATH']):
            logging.info("Loading synthetic threat data...")
            synthetic_data = pd.read_csv(app.config['DATASET_PATH'])
            return True
        else:
            logging.warning(f"Synthetic data not found at {app.config['DATASET_PATH']}")
            synthetic_data = None
            return True  # Return True so the app can continue without data
    except Exception as e:
        logging.error(f"Error loading data: {str(e)}")
        return False

def detect_threat(content):
    """
    Simulate threat detection (simplified version without ML model).
    
    Args:
        content (str): The text content to analyze
    
    Returns:
        str: The detected threat type
    """
    # List of possible threat types
    candidate_labels = ["Malware", "Phishing", "Scam", "Carding", "Exploit", "Fraud", 
                        "Hacking Services", "Ransomware", "Trojan", "Spyware", "DDoS", "SQL Injection"]
    
    try:
        # Simple keyword-based detection
        content_lower = content.lower()
        if "malware" in content_lower or "virus" in content_lower:
            return "Malware"
        elif "phish" in content_lower or "credential" in content_lower:
            return "Phishing"
        elif "ransom" in content_lower or "encrypt" in content_lower:
            return "Ransomware"
        elif "card" in content_lower or "credit" in content_lower:
            return "Carding"
        elif "hack" in content_lower or "crack" in content_lower:
            return "Hacking Services"
        elif "sql" in content_lower or "injection" in content_lower:
            return "SQL Injection"
        elif "ddos" in content_lower or "denial of service" in content_lower:
            return "DDoS"
        elif "scam" in content_lower or "scheme" in content_lower:
            return "Scam"
        else:
            # If no keywords match, return a random threat type
            return random.choice(candidate_labels)
    except Exception as e:
        logging.error(f"Error detecting threat: {str(e)}")
        return "Unknown"

def get_threat_details(threat_type):
    """
    Get threat details (severity, confidence, recommendation).
    
    Args:
        threat_type (str): The detected threat type
    
    Returns:
        dict: A dictionary containing severity, confidence_score, and recommendation
    """
    global synthetic_data
    
    # Try to load synthetic data if not already loaded
    if synthetic_data is None:
        load_model()
    
    try:
        # If we have synthetic data, try to use it
        if synthetic_data is not None:
            # Filter the synthetic data by threat type
            filtered_data = synthetic_data[synthetic_data['threat_type'].str.contains(threat_type, case=False, na=False)]
            
            if len(filtered_data) > 0:
                # Select a random row from the filtered data
                row = filtered_data.sample(1).iloc[0]
                
                return {
                    'severity': row['severity'],
                    'confidence_score': float(row['confidence_score']),
                    'recommendation': row['recommendation']
                }
        
        # If no synthetic data or no match found, return default values
        return default_threat_details(threat_type)
    except Exception as e:
        logging.error(f"Error getting threat details: {str(e)}")
        return default_threat_details(threat_type)

def default_threat_details(threat_type=None):
    """Generate default threat details when synthetic data is unavailable"""
    severity_map = {
        'Malware': 'High',
        'Ransomware': 'High',
        'Trojan': 'High',
        'Phishing': 'Medium',
        'Scam': 'Medium',
        'Fraud': 'Medium',
        'Spyware': 'Medium',
        'Exploit': 'Medium',
        'DDoS': 'Medium',
        'SQL Injection': 'Medium',
        'Carding': 'Medium',
        'Hacking Services': 'Medium',
        'Drugs': 'Low'
    }
    
    recommendation_map = {
        'Malware': 'Update antivirus signatures and scan all systems',
        'Ransomware': 'Isolate affected systems and restore from clean backups',
        'Trojan': 'Remove malicious software and analyze system for persistence',
        'Phishing': 'Educate users on identifying phishing attempts',
        'Scam': 'Report to authorities and block communication channels',
        'Fraud': 'Document evidence and contact financial institutions',
        'Spyware': 'Run anti-spyware tools and review data protection measures',
        'Exploit': 'Apply security patches to affected systems',
        'DDoS': 'Implement traffic filtering and rate limiting',
        'SQL Injection': 'Sanitize inputs and apply database security measures',
        'Carding': 'Monitor for fraudulent transactions and secure payment systems',
        'Hacking Services': 'Block IP addresses and report to authorities',
        'Drugs': 'Report to law enforcement and block communication channels'
    }
    
    severity = severity_map.get(threat_type, 'Medium')
    confidence_score = round(random.uniform(0.6, 0.9), 2)
    recommendation = recommendation_map.get(threat_type, 'Monitor and report suspicious activity')
    
    return {
        'severity': severity,
        'confidence_score': confidence_score,
        'recommendation': recommendation
    }
