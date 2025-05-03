import pandas as pd
import numpy as np
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define threat categories and their keywords
THREAT_CATEGORIES = {
    'Malware': ['malware', 'virus', 'worm', 'infection', 'trojan', 'backdoor', 'rootkit'],
    'Ransomware': ['ransom', 'encrypt', 'decrypt', 'bitcoin', 'payment', 'locked'],
    'Phishing': ['phish', 'credential', 'password', 'login', 'bank', 'account'],
    'Carding': ['card', 'credit', 'cvv', 'dump', 'fullz', 'bank'],
    'Exploit': ['exploit', 'vulnerability', 'cve', 'zero-day', 'buffer', 'overflow'],
    'Fraud': ['fraud', 'fake', 'counterfeit', 'scam', 'scheme', 'money'],
}

def clean_text(text):
    """Clean text data"""
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

def label_data(df, content_column='Post Content'):
    """
    Label data based on keywords in the content.
    Returns DataFrame with new 'threat_label' column.
    """
    df = df.copy()
    
    # Take a smaller subset for faster processing
    if len(df) > 5000:
        logger.info(f"Limiting to 5000 rows from {len(df)} total rows")
        df = df.sample(5000, random_state=42)
    
    # Clean the content
    df['clean_content'] = df[content_column].apply(clean_text)
    
    # Initialize threat label column
    df['threat_label'] = 'Unknown'
    
    # Classify based on keywords
    for threat_type, keywords in THREAT_CATEGORIES.items():
        # Check if any of the keywords are in the content
        mask = df['clean_content'].apply(lambda text: any(keyword in text for keyword in keywords))
        df.loc[mask, 'threat_label'] = threat_type
    
    # Count the occurrences of each threat type
    threat_counts = df['threat_label'].value_counts()
    logger.info("Threat type distribution:")
    for threat, count in threat_counts.items():
        logger.info(f"{threat}: {count}")
    
    return df

def train_threat_model(input_file, model_dir='models'):
    """
    Train a model to classify forum posts into threat categories.
    
    Args:
        input_file: Path to Excel file with forum data
        model_dir: Directory to save the model files
    
    Returns:
        dict: Training results with model paths
    """
    try:
        # Create model directory if it doesn't exist
        os.makedirs(model_dir, exist_ok=True)
        
        # Load the dataset
        logger.info(f"Loading dataset from {input_file}")
        df = pd.read_excel(input_file)
        
        # Basic dataset info
        logger.info(f"Dataset shape: {df.shape}")
        logger.info(f"Dataset columns: {df.columns.tolist()}")
        
        # Label the data
        logger.info("Labeling data based on content keywords")
        labeled_df = label_data(df)
        
        # Remove Unknown labels for training
        train_df = labeled_df[labeled_df['threat_label'] != 'Unknown']
        logger.info(f"Training data size after removing 'Unknown' labels: {train_df.shape[0]}")
        
        if train_df.shape[0] < 100:
            logger.warning("Very limited labeled data available for training")
            # For demonstration, add some synthetic examples
            for threat_type, keywords in THREAT_CATEGORIES.items():
                for keyword in keywords[:3]:  # Use first 3 keywords
                    example = f"This is an example of {threat_type} content containing the keyword {keyword}."
                    new_row = pd.DataFrame({
                        'clean_content': [example],
                        'threat_label': [threat_type]
                    })
                    train_df = pd.concat([train_df, new_row], ignore_index=True)
            
            logger.info(f"Added synthetic examples, new training data size: {train_df.shape[0]}")
        
        # Create features and target
        X = train_df['clean_content']
        y = train_df['threat_label']
        
        # Split into train and test sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        logger.info(f"Training set size: {X_train.shape[0]}")
        logger.info(f"Test set size: {X_test.shape[0]}")
        
        # Build model pipeline
        pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(max_features=1000, min_df=1, max_df=0.9)),
            ('classifier', MultinomialNB())
        ])
        
        # Train the model
        logger.info("Training model...")
        pipeline.fit(X_train, y_train)
        
        # Evaluate the model
        y_pred = pipeline.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        logger.info(f"Model accuracy: {accuracy:.4f}")
        logger.info("Classification report:")
        logger.info(classification_report(y_test, y_pred))
        
        # Save the pipeline with vectorizer and classifier
        model_path = os.path.join(model_dir, 'threat_model.joblib')
        joblib.dump(pipeline, model_path)
        logger.info(f"Model saved to {model_path}")
        
        # Save the threat categories to a file
        categories_path = os.path.join(model_dir, 'threat_categories.joblib')
        joblib.dump(THREAT_CATEGORIES, categories_path)
        logger.info(f"Threat categories saved to {categories_path}")
        
        return {
            'success': True,
            'model_path': model_path,
            'categories_path': categories_path,
            'accuracy': accuracy
        }
    
    except Exception as e:
        logger.error(f"Error training model: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

if __name__ == "__main__":
    # Train the model using the forum data
    result = train_threat_model('attached_assets/Book1.xlsx')
    
    if result['success']:
        logger.info("Model training completed successfully!")
    else:
        logger.error(f"Model training failed: {result.get('error', 'Unknown error')}")