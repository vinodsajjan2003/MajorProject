import os
import logging
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import torch
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
from transformers import Trainer, TrainingArguments
from torch.utils.data import Dataset
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define paths
EXCEL_PATH = 'attached_assets/Book1.xlsx'
MODEL_DIR = 'models'
MODEL_PATH = os.path.join(MODEL_DIR, 'distilbert_threat_model')
TOKENIZER_PATH = os.path.join(MODEL_DIR, 'distilbert_tokenizer')

# Create model directory if it doesn't exist
os.makedirs(MODEL_DIR, exist_ok=True)

# Maximum sequence length for BERT models
MAX_SEQ_LEN = 256

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

def label_data(df, content_column='Post Content'):
    """
    Label data based on keywords in the content.
    Returns DataFrame with new 'threat_label' column.
    """
    # Create a dictionary mapping keywords to threat types
    keyword_mapping = {
        'malware': 'Malware',
        'virus': 'Malware',
        'worm': 'Malware',
        'trojan': 'Malware',
        'ransomware': 'Ransomware',
        'ransom': 'Ransomware',
        'encrypt': 'Ransomware',
        'bitcoin': 'Ransomware',
        'phish': 'Phishing',
        'credential': 'Phishing',
        'password': 'Phishing',
        'login': 'Phishing',
        'bank': 'Phishing',
        'credit card': 'Carding',
        'card': 'Carding',
        'cvv': 'Carding',
        'hack': 'Exploit',
        'exploit': 'Exploit',
        'vulnerability': 'Exploit',
        'cve': 'Exploit',
        'fraud': 'Fraud',
        'fake': 'Fraud',
        'scam': 'Fraud'
    }
    
    # Initialize the threat_label column with 'Unknown'
    df['threat_label'] = 'Unknown'
    
    # For each row, check if any keywords are in the content
    for idx, row in df.iterrows():
        content = str(row[content_column]).lower()
        for keyword, threat_type in keyword_mapping.items():
            if keyword in content:
                df.at[idx, 'threat_label'] = threat_type
                break
    
    return df

class ThreatDataset(Dataset):
    """Dataset for threat classification with DistilBERT"""
    
    def __init__(self, texts, labels, tokenizer, max_len=MAX_SEQ_LEN):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_len = max_len
        self.label_map = {label: i for i, label in enumerate(sorted(set(labels)))}
        
    def __len__(self):
        return len(self.texts)
    
    def __getitem__(self, idx):
        text = self.texts[idx]
        label = self.labels[idx]
        
        # Tokenize the text
        encoding = self.tokenizer(
            text,
            truncation=True,
            padding='max_length',
            max_length=self.max_len,
            return_tensors='pt'
        )
        
        # Extract the tensors
        input_ids = encoding['input_ids'].squeeze()
        attention_mask = encoding['attention_mask'].squeeze()
        
        # Convert label to tensor
        label_id = torch.tensor(self.label_map[label])
        
        return {
            'input_ids': input_ids,
            'attention_mask': attention_mask,
            'labels': label_id
        }

def train_distilbert_model():
    """Train a DistilBERT model for threat classification"""
    try:
        # Load data from Excel file
        logger.info(f"Loading dataset from {EXCEL_PATH}")
        df = pd.read_excel(EXCEL_PATH)
        logger.info(f"Dataset shape: {df.shape}")
        logger.info(f"Dataset columns: {df.columns.tolist()}")
        
        # Label data based on content keywords
        logger.info("Labeling data based on content keywords")
        df = label_data(df)
        
        # Limit to a smaller dataset if needed for faster training
        MAX_ROWS = 10000
        if len(df) > MAX_ROWS:
            logger.info(f"Limiting to {MAX_ROWS} rows from {len(df)} total rows")
            df = df.sample(n=MAX_ROWS, random_state=42)
        
        # Display threat type distribution
        logger.info("Threat type distribution:")
        threat_dist = df['threat_label'].value_counts()
        for threat, count in threat_dist.items():
            logger.info(f"{threat}: {count}")
        
        # Remove rows with 'Unknown' threat label
        df = df[df['threat_label'] != 'Unknown']
        logger.info(f"Training data size after removing 'Unknown' labels: {len(df)}")
        
        # Clean text data
        df['cleaned_content'] = df['Post Content'].apply(clean_text)
        
        # Split data into train and test sets
        X = df['cleaned_content'].values
        y = df['threat_label'].values
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        logger.info(f"Training set size: {len(X_train)}")
        logger.info(f"Test set size: {len(X_test)}")
        
        # Load tokenizer and create datasets
        logger.info("Loading DistilBERT tokenizer")
        tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
        
        # Save tokenizer for later use
        tokenizer.save_pretrained(TOKENIZER_PATH)
        logger.info(f"Tokenizer saved to {TOKENIZER_PATH}")
        
        # Create datasets
        train_dataset = ThreatDataset(X_train, y_train, tokenizer)
        test_dataset = ThreatDataset(X_test, y_test, tokenizer)
        
        # Get number of labels
        num_labels = len(set(y_train))
        
        # Load pre-trained model
        logger.info(f"Loading DistilBERT model with {num_labels} labels")
        model = DistilBertForSequenceClassification.from_pretrained(
            'distilbert-base-uncased',
            num_labels=num_labels
        )
        
        # Define training arguments
        training_args = TrainingArguments(
            output_dir='./results',
            num_train_epochs=3,
            per_device_train_batch_size=8,
            per_device_eval_batch_size=8,
            warmup_steps=500,
            weight_decay=0.01,
            logging_dir='./logs',
            logging_steps=100,
            eval_steps=500,
            save_steps=1000,
            evaluation_strategy="steps",
        )
        
        # Create trainer
        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=test_dataset
        )
        
        # Train the model
        logger.info("Training model...")
        trainer.train()
        
        # Evaluate the model
        logger.info("Evaluating model...")
        eval_result = trainer.evaluate()
        logger.info(f"Evaluation results: {eval_result}")
        
        # Save the model
        logger.info(f"Saving model to {MODEL_PATH}")
        model.save_pretrained(MODEL_PATH)
        
        # Create label mapping for inference
        label_map = {i: label for i, label in enumerate(sorted(set(y_train)))}
        
        # Save the label mapping alongside the model
        import json
        with open(os.path.join(MODEL_PATH, 'label_map.json'), 'w') as f:
            json.dump(label_map, f)
        
        logger.info("Model training completed successfully!")
        return {
            'model_path': MODEL_PATH,
            'tokenizer_path': TOKENIZER_PATH,
            'num_labels': num_labels,
            'label_map': label_map,
            'evaluation': eval_result
        }
    
    except Exception as e:
        logger.error(f"Error training model: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return None

if __name__ == "__main__":
    train_distilbert_model()