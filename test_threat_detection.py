import os
import logging
from app import app
from utils.model import load_model, detect_threat, get_threat_details
from utils.scraper import scrape_url_content

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_with_content(content):
    """Test threat detection with text content"""
    logger.info(f"Testing with content: {content[:100]}...")
    
    # Detect threat
    threat_type = detect_threat(content)
    logger.info(f"Detected threat type: {threat_type}")
    
    # Get threat details
    threat_details = get_threat_details(threat_type)
    logger.info(f"Severity: {threat_details['severity']}")
    logger.info(f"Confidence score: {threat_details['confidence_score']}")
    logger.info(f"Recommendation: {threat_details['recommendation']}")
    
    # Check for additional details
    if 'description' in threat_details and threat_details['description']:
        logger.info(f"Description: {threat_details['description']}")
    if 'ioc' in threat_details and threat_details['ioc']:
        logger.info(f"IoC: {threat_details['ioc']}")
    if 'source' in threat_details and threat_details['source']:
        logger.info(f"Source: {threat_details['source']}")
    
    return threat_type, threat_details

def test_with_url(url):
    """Test threat detection by scraping a URL"""
    logger.info(f"Testing with URL: {url}")
    
    # Scrape content
    content = scrape_url_content(url)
    if not content:
        logger.error("Failed to scrape content from URL")
        return None, None
    
    # Test with the scraped content
    return test_with_content(content)

def main():
    with app.app_context():
        # Load the model
        logger.info("Loading model...")
        load_model()
        
        # Test with sample texts
        logger.info("\n=== Testing with sample texts ===")
        test_with_content("This website offers fake identification documents and passports for purchase.")
        test_with_content("Our ransomware service encrypts all files and demands payment in bitcoin.")
        test_with_content("We provide access to stolen credit card data with full CVV codes.")
        test_with_content("This exploit allows you to bypass SQL database security using injection techniques.")
        
        # Test with URLs (if desired)
        # logger.info("\n=== Testing with sample URLs ===")
        # test_with_url("https://example.com")

if __name__ == "__main__":
    main()