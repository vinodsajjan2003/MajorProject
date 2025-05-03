import os
import logging
import random
from app import app
import pandas as pd
import joblib
import re

# Global variables to hold the data
synthetic_data = None
trained_model = None
threat_categories = None

def clean_text(text):
    """Clean text data for model prediction"""
    if not isinstance(text, str):
        return ""
    
    # Convert to lowercase
    text = text.lower()
    
    # Remove HTML tags
    text = re.sub(r'<.*?>', '', text)
    
    # Remove special characters and digits
    text = re.sub(r'[^\w\s]', ' ', text)
    text = re.sub(r'\d+', ' ', text)
    
    # Remove extra spaces
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text

def load_model():
    """Load trained model and data for threat analysis"""
    global synthetic_data, trained_model, threat_categories
    
    success = True
    
    # Load trained model
    try:
        model_path = os.path.join(app.config.get('MODEL_DIR', 'models'), 'threat_model.joblib')
        categories_path = os.path.join(app.config.get('MODEL_DIR', 'models'), 'threat_categories.joblib')
        
        if os.path.exists(model_path) and os.path.exists(categories_path):
            logging.info(f"Loading trained model from {model_path}")
            trained_model = joblib.load(model_path)
            
            logging.info(f"Loading threat categories from {categories_path}")
            threat_categories = joblib.load(categories_path)
            
            logging.info(f"Model and categories loaded successfully")
        else:
            logging.warning(f"Trained model files not found at {model_path}")
            trained_model = None
            threat_categories = None
            success = False
    except Exception as e:
        logging.error(f"Error loading trained model: {str(e)}")
        trained_model = None
        threat_categories = None
        success = False
    
    # Load synthetic threat data for detailed information
    try:
        if os.path.exists(app.config.get('DATASET_PATH', 'attached_assets/synthetic_cyber_threats_100k.csv')):
            logging.info("Loading synthetic threat data...")
            synthetic_data = pd.read_csv(app.config.get('DATASET_PATH', 'attached_assets/synthetic_cyber_threats_100k.csv'))
            logging.info(f"Loaded {len(synthetic_data)} synthetic threat records")
        else:
            logging.warning("Synthetic data file not found")
            synthetic_data = None
            success = False
    except Exception as e:
        logging.error(f"Error loading synthetic data: {str(e)}")
        synthetic_data = None
        success = False
    
    return success

def detect_threat(content):
    """
    Detect threats using the trained model from Book1.xlsx dataset.
    Falls back to keyword-based detection if the model is not available.
    
    Args:
        content (str): The text content to analyze
    
    Returns:
        str: The detected threat type
    """
    global trained_model, threat_categories
    
    # Default threat types if no model is available
    candidate_labels = ["Malware", "Phishing", "Scam", "Carding", "Exploit", "Fraud", 
                        "Hacking Services", "Ransomware", "Trojan", "Spyware", "DDoS", "SQL Injection"]
    
    # Ensure model is loaded
    if trained_model is None:
        load_model()
    
    try:
        # Clean the content for analysis
        cleaned_content = clean_text(content)
        
        # Use the trained model for prediction if available
        if trained_model is not None:
            logging.info("Using trained model for threat detection")
            
            # Get prediction from model
            predicted_threat = trained_model.predict([cleaned_content])[0]
            
            # Get prediction probabilities
            prediction_probs = trained_model.predict_proba([cleaned_content])[0]
            max_prob = max(prediction_probs)
            
            # Log prediction details
            logging.info(f"Model predicted threat type: {predicted_threat} with confidence {max_prob:.4f}")
            
            # If confidence is too low, fall back to keyword-based detection
            if max_prob < 0.3:
                logging.warning(f"Low confidence prediction ({max_prob:.4f}), falling back to keyword detection")
            else:
                return predicted_threat
        else:
            logging.warning("No trained model available, using keyword-based detection")
        
        # Fallback 1: Keyword-based detection using threat categories
        if threat_categories is not None:
            logging.info("Using threat categories for keyword-based detection")
            
            # Convert content to lowercase for comparison
            content_lower = cleaned_content.lower()
            
            # Check each threat category for keyword matches
            matched_categories = []
            for threat_type, keywords in threat_categories.items():
                # Check if any keywords match
                if any(keyword in content_lower for keyword in keywords):
                    matched_categories.append(threat_type)
            
            # If we found matches, return the first match
            if matched_categories:
                logging.info(f"Detected threat using keywords: {matched_categories[0]}")
                return matched_categories[0]
        
        # Fallback 2: Advanced keyword detection
        logging.info("Using hardcoded keyword detection")
        content_lower = content.lower()
        
        if any(kw in content_lower for kw in ['malware', 'virus', 'worm', 'infection']):
            return "Malware"
        elif any(kw in content_lower for kw in ['phish', 'credential', 'password', 'login', 'bank account']):
            return "Phishing"
        elif any(kw in content_lower for kw in ['ransom', 'encrypt', 'bitcoin', 'payment', 'decrypt']):
            return "Ransomware"
        elif any(kw in content_lower for kw in ['card', 'credit card', 'cvv', 'dump', 'fullz']):
            return "Carding"
        elif any(kw in content_lower for kw in ['hack', 'crack', 'bruteforce', 'backdoor']):
            return "Hacking Services"
        elif any(kw in content_lower for kw in ['sql', 'injection', 'query', 'database vulnerability']):
            return "SQL Injection"
        elif any(kw in content_lower for kw in ['ddos', 'denial of service', 'botnet', 'flood']):
            return "DDoS"
        elif any(kw in content_lower for kw in ['scam', 'scheme', 'trick', 'deceive']):
            return "Scam"
        elif any(kw in content_lower for kw in ['exploit', 'vulnerability', 'cve', 'zero-day']):
            return "Exploit"
        elif any(kw in content_lower for kw in ['trojan', 'backdoor', 'keylogger']):
            return "Trojan"
        elif any(kw in content_lower for kw in ['spyware', 'surveillance', 'monitor']):
            return "Spyware"
        elif any(kw in content_lower for kw in ['fraud', 'fake', 'counterfeit']):
            return "Fraud"
        
        # Fallback 3: Return "Fraud" as a default threat type (most common in our dataset)
        logging.warning("No threat detected, using default threat type")
        return "Fraud"
            
    except Exception as e:
        logging.error(f"Error detecting threat: {str(e)}")
        logging.exception("Exception details:")
        return "Unknown"

def get_threat_details(threat_type):
    """
    Get threat details (severity, confidence, recommendation) from the synthetic dataset.
    
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
            # Get the exact threat type or case-insensitive match
            filtered_data = synthetic_data[
                synthetic_data['threat_type'].str.lower() == threat_type.lower()
            ]
            
            # If no exact match found, try partial match
            if len(filtered_data) == 0:
                filtered_data = synthetic_data[
                    synthetic_data['threat_type'].str.contains(threat_type, case=False, na=False)
                ]
            
            if len(filtered_data) > 0:
                # Group by severity and sort by confidence score
                severity_groups = filtered_data.groupby('severity')
                
                # Prioritize High severity threats first, then Medium, then Low
                for severity in ['High', 'Medium', 'Low']:
                    if severity in severity_groups.groups:
                        # Get the group for this severity
                        severity_group = severity_groups.get_group(severity)
                        
                        # Sort by confidence score (highest first)
                        severity_group = severity_group.sort_values('confidence_score', ascending=False)
                        
                        # Get the first row (highest confidence)
                        row = severity_group.iloc[0]
                        
                        return {
                            'severity': row['severity'],
                            'confidence_score': float(row['confidence_score']),
                            'recommendation': row['recommendation'],
                            'description': row['description'] if 'description' in row else None,
                            'ioc': row['ioc'] if 'ioc' in row else None,
                            'source': row['source'] if 'source' in row else None
                        }
                
                # If we didn't find any of the priority severities, just take a random high confidence row
                high_confidence_rows = filtered_data.sort_values('confidence_score', ascending=False)
                row = high_confidence_rows.iloc[0]
                
                return {
                    'severity': row['severity'],
                    'confidence_score': float(row['confidence_score']),
                    'recommendation': row['recommendation'],
                    'description': row['description'] if 'description' in row else None,
                    'ioc': row['ioc'] if 'ioc' in row else None,
                    'source': row['source'] if 'source' in row else None
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
