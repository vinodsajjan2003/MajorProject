# ThreatShield - Dark Web URL Threat Detector

ThreatShield is a Flask-based web application that detects and analyzes threats from dark web URLs. It uses a SentenceTransformer-based model to classify content into various threat categories and generates comprehensive threat intelligence reports.

## Features

- **Advanced Threat Detection**: Uses SentenceTransformer models to classify web content into threat categories
- **Comprehensive Reporting**: Generates detailed threat reports with severity, confidence scores, and recommendations
- **User Authentication**: Secure login and registration system
- **PDF Reports**: Download threat reports as PDF documents
- **Email Notifications**: Send threat reports via email

## Technical Implementation

### SentenceTransformer Model

The application uses the `sentence-transformers` library to encode text content and classify it into threat categories. This implementation follows the same approach as in the `mid.py` reference file:

```python
from sentence_transformers import SentenceTransformer, util

model = SentenceTransformer('all-MiniLM-L6-v2', device='cpu')
candidate_labels = ["Malware", "Phishing", "Ransomware", "Carding", "Exploit", "Fraud", "Hacking Services", "Scam"]
label_embeddings = model.encode(candidate_labels, convert_to_tensor=True)

def label_threat(content):
    content_embedding = model.encode(str(content), convert_to_tensor=True)
    cos_scores = util.cos_sim(content_embedding, label_embeddings)
    best_label_idx = cos_scores.argmax()
    return candidate_labels[best_label_idx]
```

### Data Sources

The application uses two main data sources:

1. **Book1.xlsx** - Contains ~33,416 forum posts used for training the threat classification model
2. **synthetic_cyber_threats_100k.csv** - Contains 100,000 synthetic threat records with detailed information about each threat type

### Fallback Mechanism

If the SentenceTransformer model is not available, the application automatically falls back to a keyword-based classification system that follows the same approach.

## Project Structure

- `app.py` - Flask application configuration and initialization
- `config.py` - Application configuration settings
- `forms.py` - Form classes for user input
- `models.py` - Database models for users and scan results
- `routes.py` - Application routes and controllers
- `main.py` - Application entry point
- `train_distilbert_model.py` - Script to train the SentenceTransformer model
- `test_distilbert_detection.py` - Test script for the threat detection system
- `utils/`
  - `distilbert_model.py` - Core threat detection and analysis implementation
  - `scraper.py` - Web content scraping functionality
  - `report.py` - Report generation functionality

## Running the Application Locally

1. Install the required dependencies:
   ```
   pip install flask flask-login flask-wtf flask-sqlalchemy fpdf
   pip install sentence-transformers torch pandas joblib trafilatura
   ```

2. Start the application:
   ```
   python main.py
   ```

3. Access the application in your browser at `http://localhost:5000`

### Email Functionality

The application uses Gmail SMTP to send email reports. The email functionality is already configured with:

- Sender email: businessbusinessman97@gmail.com
- App password: [Already configured in code]

If you need to use a different email account:
1. Generate an app password for your Google account
2. Update the settings in `utils/email_sender.py`

## Training the Model

To train or retrain the SentenceTransformer model:

```
python train_distilbert_model.py
```

This will load data from Book1.xlsx, process it with SentenceTransformer, and save the model and label embeddings to the models directory.