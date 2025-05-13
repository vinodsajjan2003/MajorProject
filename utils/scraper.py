import requests
import logging
from app import app
import trafilatura
import time
import random
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import os
import logging
from config import Config

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def scrape_url_content(url):
    """
    Scrape content from a given URL.
    Supports both regular and .onion URLs.
    
    Returns: Extracted text content from the URL.
    """
    # Configure the request settings
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    # Check if it's an .onion URL
    if '.onion' in url:
        # Use Tor proxy for .onion URLs
        proxies = {
            'http': f'socks5h://{Config.TOR_PROXY_HOST}:{Config.TOR_PROXY_PORT}',
            'https': f'socks5h://{Config.TOR_PROXY_HOST}:{Config.TOR_PROXY_PORT}'
        }
        logger.info(f"Scraping onion URL using proxy {Config.TOR_PROXY_HOST}:{Config.TOR_PROXY_PORT}")
    else:
        proxies = None
    
    try:
        logger.info(f"Attempting to scrape: {url}")
        
        # First try with trafilatura
        try:
            downloaded = trafilatura.fetch_url(url)
            if downloaded:
                text = trafilatura.extract(downloaded)
                if text and len(text) > 100:  # Ensure we got meaningful content
                    logger.info(f"Successfully scraped with trafilatura: {len(text)} characters")
                    return text
                logger.warning("Trafilatura returned insufficient content, falling back to requests")
            else:
                logger.warning("Trafilatura failed to download URL, falling back to requests")
        except Exception as trafilatura_error:
            logger.warning(f"Trafilatura error: {str(trafilatura_error)}, falling back to requests")
        
        # Fallback to direct requests if trafilatura fails
        response = requests.get(url, headers=headers, proxies=proxies, timeout=60)
        
        # Check if the request was successful
        if response.status_code == 200:
            # Use trafilatura to extract content from HTML
            text = trafilatura.extract(response.text)
            
            # If trafilatura extraction fails, return the raw HTML as a last resort
            if not text or len(text) < 100:
                logger.warning("Trafilatura extraction failed, returning a portion of raw HTML")
                # Just take a portion of the HTML to have something to analyze
                text = response.text[:10000]
            
            logger.info(f"Successfully scraped {len(text)} characters from {url}")
            return text
        else:
            logger.error(f"Failed to retrieve content from {url}: Status Code {response.status_code}")
            return f"Failed to access URL: HTTP {response.status_code}"
            
    except Exception as e:
        logger.error(f"Error scraping {url}: {str(e)}")
        return f"Error accessing URL: {str(e)}"
