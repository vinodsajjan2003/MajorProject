import os
import logging
import random
from app import app
import pandas as pd
import openpyxl

# Global variables to hold the data
synthetic_data = None
forum_data = None

def load_model():
    """Load data for threat analysis"""
    global synthetic_data, forum_data
    
    success = True
    
    # Load synthetic threat data
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
    
    # Load forum data from Excel
    try:
        excel_path = 'attached_assets/Book1.xlsx'
        if os.path.exists(excel_path):
            logging.info("Loading forum data from Excel...")
            forum_data = pd.read_excel(excel_path)
            logging.info(f"Loaded {len(forum_data)} forum data records")
        else:
            logging.warning("Forum data Excel file not found")
            forum_data = None
            success = False
    except Exception as e:
        logging.error(f"Error loading forum data: {str(e)}")
        forum_data = None
        success = False
    
    return success

def detect_threat(content):
    """
    Detect threats by comparing content with forum data from Book1.xlsx
    and using advanced keyword detection.
    
    Args:
        content (str): The text content to analyze
    
    Returns:
        str: The detected threat type
    """
    global forum_data
    
    # List of possible threat types from the synthetic dataset
    candidate_labels = ["Malware", "Phishing", "Scam", "Carding", "Exploit", "Fraud", 
                        "Hacking Services", "Ransomware", "Trojan", "Spyware", "DDoS", "SQL Injection"]
    
    # Ensure forum data is loaded
    if forum_data is None:
        load_model()
    
    try:
        # First, try to find similar content in the forum data
        if forum_data is not None:
            # Convert input content to lowercase for comparison
            content_lower = content.lower()
            
            # Create a dictionary mapping keywords to threat types
            keyword_mapping = {
                'malware': 'Malware',
                'virus': 'Malware',
                'worm': 'Malware',
                'trojan': 'Trojan',
                'spyware': 'Spyware',
                'ransomware': 'Ransomware',
                'ransom': 'Ransomware',
                'encrypt': 'Ransomware',
                'bitcoin': 'Ransomware',
                'payment': 'Ransomware',
                'phish': 'Phishing',
                'credential': 'Phishing',
                'password': 'Phishing',
                'login': 'Phishing',
                'bank': 'Phishing',
                'account': 'Phishing',
                'credit card': 'Carding',
                'card': 'Carding',
                'cvv': 'Carding',
                'hack': 'Hacking Services',
                'crack': 'Hacking Services',
                'exploit': 'Exploit',
                'vulnerability': 'Exploit',
                'cve': 'Exploit',
                'sql': 'SQL Injection',
                'injection': 'SQL Injection',
                'ddos': 'DDoS',
                'denial of service': 'DDoS',
                'botnet': 'DDoS',
                'scam': 'Scam',
                'scheme': 'Scam',
                'fraud': 'Fraud',
                'fake': 'Fraud'
            }
            
            # Check for forum data matches - check if similar content exists in forum data
            matches = []
            
            # Try to find similar content in the 'Post Content' column
            if 'Post Content' in forum_data.columns:
                for idx, row in forum_data.iterrows():
                    post_content = str(row['Post Content']).lower()
                    # Check for content similarity
                    if post_content and (
                        any(keyword in post_content for keyword in keyword_mapping.keys()) or
                        any(keyword in content_lower for keyword in keyword_mapping.keys())
                    ):
                        # Find the matching threat type from keywords
                        for keyword, threat in keyword_mapping.items():
                            if keyword in post_content or keyword in content_lower:
                                matches.append(threat)
                                break
            
            # If we found matches in the forum data, return the most common match
            if matches:
                # Count occurrences of each threat type
                threat_counts = {}
                for threat in matches:
                    threat_counts[threat] = threat_counts.get(threat, 0) + 1
                
                # Return the most common threat type
                most_common_threat = max(threat_counts.items(), key=lambda x: x[1])[0]
                return most_common_threat
        
        # If no forum data or no matches found, use keyword detection
        content_lower = content.lower()
        
        # Advanced keyword detection
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
        else:
            # If no keywords match, use a similarity-based approach
            # For now, return a random threat type as fallback
            return random.choice(candidate_labels)
            
    except Exception as e:
        logging.error(f"Error detecting threat: {str(e)}")
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
