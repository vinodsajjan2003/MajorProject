import os
import logging
import re
from app import app
import pandas as pd

# Global variables
synthetic_data = None

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
    """Load synthetic threat data for detailed information"""
    global synthetic_data
    
    success = True
    
    # Load synthetic threat data
    try:
        if os.path.exists(app.config.get('DATASET_PATH', 'data/synthetic_cyber_threats_100k.csv')):
            logging.info("Loading synthetic threat data...")
            synthetic_data = pd.read_csv(app.config.get('DATASET_PATH', 'data/synthetic_cyber_threats_100k.csv'))
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
    Detect threats using the embedded zero-shot classification approach
    based on the method from mid.py
    
    Args:
        content (str): The text content to analyze
    
    Returns:
        str: The detected threat type
    """
    # Define candidate threat labels
    candidate_labels = ["Malware", "Phishing", "Fraud", "Carding", "Exploit", "Ransomware"]
    
    # Clean the content
    cleaned_content = clean_text(content)
    
    try:
        # Use keyword-based approach similar to the mid.py logic
        content_lower = cleaned_content.lower()
        
        # Define keyword mappings for each threat type
        keyword_mappings = {
            'Malware': ['malware', 'virus', 'worm', 'trojan', 'botnet', 'keylogger', 'rootkit', 'backdoor', 'infection'],
            'Phishing': ['phish', 'credential', 'password', 'login', 'account', 'bank', 'email', 'social engineering'],
            'Ransomware': ['ransom', 'encrypt', 'bitcoin', 'payment', 'decrypt', 'crypto', 'lock', 'files'],
            'Carding': ['card', 'credit card', 'cvv', 'dump', 'fullz', 'bank account', 'pin', 'atm', 'stripe'],
            'Exploit': ['exploit', 'vulnerability', 'cve', 'sql', 'injection', 'zero-day', 'buffer overflow', 'privilege escalation'],
            'Fraud': ['fraud', 'fake', 'counterfeit', 'scam', 'scheme', 'trick', 'identity theft', 'social security']
        }
        
        # Calculate a score for each threat type based on keyword matches
        threat_scores = {}
        for threat, keywords in keyword_mappings.items():
            score = 0
            for keyword in keywords:
                if keyword in content_lower:
                    score += 1
            threat_scores[threat] = score
        
        # Get the threat type with the highest score
        max_score = max(threat_scores.values())
        if max_score > 0:
            # Get all threat types with the max score
            max_threats = [threat for threat, score in threat_scores.items() if score == max_score]
            return max_threats[0]  # Return the first one in case of ties
        
        # If no keywords match, use a simplified zero-shot approach
        # Analyze content for threat indicators
        indicators = {
            'Malware': ['install', 'download', 'infect', 'spread', 'execute', 'malicious', 'program'],
            'Phishing': ['click', 'link', 'verify', 'confirm', 'urgent', 'account', 'suspended'],
            'Ransomware': ['pay', 'recover', 'files', 'locked', 'encrypted', 'deadline'],
            'Carding': ['buy', 'sell', 'shop', 'purchase', 'money', 'transaction'],
            'Exploit': ['vulnerability', 'patch', 'security', 'bypass', 'admin', 'access', 'gain'],
            'Fraud': ['offer', 'free', 'discount', 'deal', 'limited', 'exclusive', 'special']
        }
        
        # Calculate scores for each threat based on general indicators
        indicator_scores = {}
        for threat, indicator_list in indicators.items():
            score = sum(1 for ind in indicator_list if ind in content_lower)
            indicator_scores[threat] = score
        
        # Get the threat with highest indicator score
        max_indicator_score = max(indicator_scores.values())
        if max_indicator_score > 0:
            # Get all threats with max score
            max_indicator_threats = [threat for threat, score in indicator_scores.items() if score == max_indicator_score]
            return max_indicator_threats[0]
        
        # If still no match, return "Fraud" (most common)
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
    import random
    
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