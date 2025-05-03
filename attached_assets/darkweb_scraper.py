import requests
from bs4 import BeautifulSoup
import csv
import time

# Tor proxy
proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

headers = {
    'User-Agent': 'Mozilla/5.0'
}

# Output CSV file
csv_file = 'data/darkweb_posts.csv'

# Prepare CSV
with open(csv_file, mode='w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['url', 'post_content'])

# Read onion URLs
with open('urls.txt', 'r') as f:
    urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

total_posts = 0

for url in urls:
    print(f"🔍 Scraping: {url}")
    try:
        response = requests.get(url, headers=headers, proxies=proxies, timeout=60)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract all post-like content (example: <p>, <div>, etc.)
            paragraphs = soup.find_all(['p', 'div', 'span'])

            post_texts = [p.get_text(strip=True) for p in paragraphs if len(p.get_text(strip=True)) > 30]

            with open(csv_file, mode='a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                for post in post_texts:
                    writer.writerow([url, post])
                    total_posts += 1

            print(f"✅ {len(post_texts)} posts saved from {url}")
        else:
            print(f"❌ Failed: Status Code {response.status_code}")
    except Exception as e:
        print(f"⚠️ Error with {url}: {e}")

    time.sleep(5)  # Pause between sites to avoid detection

print(f"\n🎉 Done! Total posts collected: {total_posts}")
