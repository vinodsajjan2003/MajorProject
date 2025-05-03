import requests
import logging
from app import app
import trafilatura
import time
import random
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# List of user agents for rotation
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
]

def get_random_user_agent():
    """Return a random user agent from the list"""
    return random.choice(USER_AGENTS)

def is_valid_url(url):
    """Check if the URL is valid"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def normalize_url(url):
    """Normalize URL by adding http:// if missing"""
    if not url.startswith(('http://', 'https://')):
        return 'http://' + url
    return url

def scrape_url_content(url):
    """
    Scrape content from a URL using Trafilatura with fallback to BeautifulSoup.
    
    Args:
        url (str): The URL to scrape
    
    Returns:
        str: The extracted text content from the URL
    """
    if not url:
        return "Error: No URL provided"
    
    # Normalize URL
    url = normalize_url(url)
    
    # Validate URL
    if not is_valid_url(url):
        return f"Error: Invalid URL format: {url}"
    
    try:
        # Configure headers with random user agent for stealth
        headers = {
            'User-Agent': get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml',
            'Accept-Language': 'en-US,en;q=0.5',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # First try with trafilatura's built-in fetcher
        logging.info(f"Attempting to scrape URL with trafilatura: {url}")
        downloaded = trafilatura.fetch_url(url)
        if downloaded:
            logging.info("Successfully downloaded with trafilatura")
            # Extract main content with trafilatura (which handles boilerplate removal)
            text = trafilatura.extract(downloaded, include_comments=False, include_tables=True)
            if text and len(text.strip()) > 100:  # Ensure we got meaningful content
                logging.info(f"Successfully extracted content with trafilatura: {len(text)} chars")
                return text
        
        # If trafilatura fetch fails or returns insufficient content, try requests
        logging.info(f"Trafilatura direct fetch failed or returned insufficient content, trying requests...")
        
        # Try to connect using Tor proxy if available
        try:
            tor_config = getattr(app.config, 'TOR_PROXY', None)
            if tor_config:
                response = requests.get(
                    url, 
                    headers=headers, 
                    proxies=tor_config, 
                    timeout=60
                )
                logging.info("Successfully connected using Tor proxy")
            else:
                # If TOR_PROXY not configured, use direct connection
                response = requests.get(url, headers=headers, timeout=60)
                logging.info("Successfully connected directly (no Tor proxy configured)")
                
        except Exception as e:
            logging.warning(f"Failed to connect using Tor proxy, trying direct connection: {str(e)}")
            # Fall back to direct connection if Tor is not available
            response = requests.get(url, headers=headers, timeout=60)
            logging.info("Successfully connected directly (Tor proxy failed)")
        
        # If we have a response from requests, try extraction methods
        if response.status_code == 200:
            # First try trafilatura on the response content
            text = trafilatura.extract(response.text, include_comments=False, include_tables=True)
            
            if text and len(text.strip()) > 100:
                logging.info(f"Successfully extracted content with trafilatura from response: {len(text)} chars")
                return text
            
            # If trafilatura fails, try BeautifulSoup
            logging.info("Trafilatura extraction failed, trying BeautifulSoup...")
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Remove script and style elements
            for script_or_style in soup(['script', 'style', 'meta', 'noscript']):
                script_or_style.decompose()
            
            # Get page text
            text = soup.get_text()
            
            # Clean the text
            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            text = '\n'.join(chunk for chunk in chunks if chunk)
            
            if text and len(text.strip()) > 100:
                logging.info(f"Successfully extracted content with BeautifulSoup: {len(text)} chars")
                # Limit text to a reasonable size
                return text[:10000] if len(text) > 10000 else text
            else:
                # If both extraction methods fail, return a portion of the raw HTML
                logging.warning("Both extraction methods failed, returning partial raw HTML")
                return f"Raw content (extraction failed): {response.text[:5000]}"
        else:
            logging.error(f"Failed to scrape URL: HTTP status {response.status_code}")
            return f"Error: Failed to access URL (HTTP status {response.status_code})"
    
    except Exception as e:
        logging.error(f"Error scraping URL {url}: {str(e)}")
        return f"Error: Failed to scrape content due to: {str(e)}"
