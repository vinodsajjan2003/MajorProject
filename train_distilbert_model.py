import os
import logging
import pandas as pd
import re
from sentence_transformers import SentenceTransformer, util
import torch

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define paths
EXCEL_PATH = 'attached_assets/Book1.xlsx'
MODEL_DIR = 'models'
os.makedirs(MODEL_DIR, exist_ok=True)

# Define candidate labels for threat classification
CANDIDATE_LABELS = [
    "Malware", "Phishing", "Ransomware", "Carding", "Exploit", "Fraud", 
    "Hacking Services", "Scam", "Trojan", "Spyware", "DDoS", "SQL Injection"
]

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
    
    # Remove extra spaces
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text

def label_threat(content, model, label_embeddings):
    """
    Label threat using sentence transformer model and cosine similarity.
    
    Args:
        content (str): Text content to classify
        model: SentenceTransformer model
        label_embeddings: Pre-computed embeddings for candidate labels
        
    Returns:
        str: Detected threat type
    """
    content_embedding = model.encode(str(content), convert_to_tensor=True)
    cos_scores = util.cos_sim(content_embedding, label_embeddings)
    best_label_idx = cos_scores.argmax()
    return CANDIDATE_LABELS[best_label_idx]

def train_with_sentence_transformer():
    """
    Train a threat classification model using SentenceTransformer approach.
    This follows the approach in mid.py.
    """
    try:
        # Load data from Excel file
        logger.info(f"Loading dataset from {EXCEL_PATH}")
        df = pd.read_excel(EXCEL_PATH)
        logger.info(f"Dataset shape: {df.shape}")
        logger.info(f"Dataset columns: {df.columns.tolist()}")
        
        # Clean text data
        logger.info("Cleaning text data...")
        df['cleaned_content'] = df['Post Content'].apply(clean_text)
        
        # Initialize SentenceTransformer model
        # Use CPU for compatibility with different environments
        logger.info("Initializing SentenceTransformer model...")
        model = SentenceTransformer('all-MiniLM-L6-v2', device='cpu')
        
        # Generate embeddings for candidate labels
        logger.info("Generating embeddings for candidate labels...")
        label_embeddings = model.encode(CANDIDATE_LABELS, convert_to_tensor=True)
        
        # Apply threat labeling using the model
        logger.info("Labeling data with SentenceTransformer...")
        
        # Process in smaller batches to prevent memory issues
        batch_size = 1000
        for i in range(0, len(df), batch_size):
            end_idx = min(i + batch_size, len(df))
            logger.info(f"Processing batch {i} to {end_idx}...")
            batch = df.iloc[i:end_idx]
            
            for idx, row in batch.iterrows():
                df.at[idx, 'threat_label'] = label_threat(
                    row['cleaned_content'], 
                    model, 
                    label_embeddings
                )
        
        # Display threat type distribution
        logger.info("Threat type distribution:")
        threat_dist = df['threat_label'].value_counts()
        for threat, count in threat_dist.items():
            logger.info(f"{threat}: {count}")
        
        # Save the model and label embeddings
        logger.info(f"Saving model and embeddings to {MODEL_DIR}")
        model.save(os.path.join(MODEL_DIR, 'sentence_transformer_model'))
        torch.save(label_embeddings, os.path.join(MODEL_DIR, 'label_embeddings.pt'))
        
        # Save the labeled data for reference
        output_path = os.path.join(MODEL_DIR, 'labeled_data.csv')
        df.to_csv(output_path, index=False)
        logger.info(f"Labeled data saved to {output_path}")
        
        logger.info("Model training completed successfully!")
        return {
            'model_path': os.path.join(MODEL_DIR, 'sentence_transformer_model'),
            'embeddings_path': os.path.join(MODEL_DIR, 'label_embeddings.pt'),
            'labeled_data_path': output_path
        }
    
    except Exception as e:
        logger.error(f"Error training model: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return None

if __name__ == "__main__":
    train_with_sentence_transformer()