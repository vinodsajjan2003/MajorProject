import os
import requests
import logging
import time
import random
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import trafilatura
from config import Config

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# List of user agents for rotation
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
]

# Tor proxy configuration
TOR_PROXIES = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

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

def is_onion_url(url):
    """Check if the URL is an .onion URL (Tor hidden service)"""
    if not url:
        return False
    parsed_url = urlparse(url)
    return parsed_url.netloc.endswith('.onion')

def scrape_with_bs4(url, is_onion=False):
    """
    Scrape content from a URL using Beautiful Soup
    
    Args:
        url (str): The URL to scrape
        is_onion (bool): Whether the URL is an .onion URL
        
    Returns:
        str: The extracted text content
    """
    headers = {'User-Agent': get_random_user_agent()}
    
    try:
        # Use Tor proxy for .onion URLs
        proxies = TOR_PROXIES if is_onion else None
        timeout = 60 if is_onion else 30
        
        logger.info(f"Requesting URL: {url} with {'Tor proxy' if is_onion else 'direct connection'}")
        response = requests.get(url, headers=headers, proxies=proxies, timeout=timeout)
        
        if response.status_code != 200:
            return f"Error: Failed to retrieve content (Status code: {response.status_code})"
        
        # Parse with BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.extract()
            
        # Extract all paragraphs, divs with significant text
        content_tags = soup.find_all(['p', 'div', 'article', 'section', 'main', 'h1', 'h2', 'h3', 'h4', 'h5', 'span'])
        content_texts = []
        
        for tag in content_tags:
            text = tag.get_text(strip=True)
            if len(text) > 30:  # Only include substantial text
                content_texts.append(text)
        
        # Join all the text with newlines
        full_content = "\n\n".join(content_texts)
        
        # If we got no significant content, try a different approach
        if not full_content.strip():
            # Get all text from the body
            body = soup.find('body')
            if body:
                full_content = body.get_text(separator="\n\n", strip=True)
        
        return full_content if full_content.strip() else f"Warning: No significant content found at {url}"
    
    except requests.exceptions.Timeout:
        return f"Error: Request timed out for {url}"
    except requests.exceptions.ConnectionError:
        return f"Error: Connection failed for {url}"
    except Exception as e:
        logger.error(f"Error scraping {url}: {str(e)}")
        return f"Error: Failed to scrape content: {str(e)}"

def scrape_with_trafilatura(url):
    """
    Scrape content using trafilatura library which is optimized for text extraction
    
    Args:
        url (str): The URL to scrape
        
    Returns:
        str: The extracted text content
    """
    try:
        logger.info(f"Fetching URL with trafilatura: {url}")
        downloaded = trafilatura.fetch_url(url)
        
        if downloaded is None:
            return None
            
        text = trafilatura.extract(downloaded)
        return text if text else None
    
    except Exception as e:
        logger.error(f"Trafilatura error with {url}: {str(e)}")
        return None

def scrape_url_content(url):
    """
    Scrape content from a URL using multiple methods with fallbacks.
    
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
        
    # Check if it's an onion URL
    onion_url = is_onion_url(url)
    
    # For regular URLs, first try trafilatura as it gives cleaner results
    if not onion_url:
        logger.info(f"Attempting to scrape regular URL with trafilatura: {url}")
        content = scrape_with_trafilatura(url)
        
        # If trafilatura worked, return the result
        if content and len(content) > 100:
            logger.info(f"Successfully scraped URL with trafilatura: {url}")
            return content
        
        # If trafilatura failed, try BS4
        logger.info(f"Trafilatura failed or returned minimal content, trying BeautifulSoup: {url}")
    
    # For onion URLs or if trafilatura failed, use BS4
    content = scrape_with_bs4(url, is_onion=onion_url)
    logger.info(f"BeautifulSoup scraping completed for: {url}")
    
    # If we still don't have much content, provide a message
    if not content or len(content) < 50:
        if onion_url:
            return f"Limited content retrieved from .onion URL: {url}. This may be due to Tor connection issues or the site being offline."
        else:
            return f"Limited content retrieved from URL: {url}. The page may be dynamic, require authentication, or have restricted content."
    
    return content
