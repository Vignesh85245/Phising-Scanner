import re
import requests
import tldextract

# URLs to your raw GitHub files (must be RAW links, not blob links)
DOMAINS_URL = "https://github.com/Vignesh85245/Phising-Scanner/blob/main/Phishing.Database-master/Lists/Phishing_domains.txt"
KEYWORDS_URL = "https://github.com/Vignesh85245/Phising-Scanner/blob/main/Phishing.Database-master/Lists/phishing_keywords.txt"

def load_malicious_domains_from_github(url):
    response = requests.get(url)
    response.raise_for_status()
    domains = [line.strip() for line in response.text.splitlines() if line.strip()]
    return domains

def load_malicious_keywords_from_github(url):
    response = requests.get(url)
    response.raise_for_status()
    keywords_dict = {}
    for line in response.text.splitlines():
        line = line.strip()
        if not line or ':' not in line:
            continue
        category, keywords_str = line.split(':', 1)
        keywords = [kw.strip() for kw in keywords_str.split(',') if kw.strip()]
        keywords_dict[category.strip()] = keywords
    return keywords_dict

# Load malicious indicators
malicious_domains = load_malicious_domains_from_github(DOMAINS_URL)
malicious_keywords = load_malicious_keywords_from_github(KEYWORDS_URL)

def check_link(link):
    # Check against keywords
    for category, keywords in malicious_keywords.items():
        for word in keywords:
            # Escape keyword to avoid invalid regex patterns
            if re.search(re.escape(word), link, re.IGNORECASE):
                return True

    # Check for raw IP addresses
    if re.search(r'http[s]?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}', link):
        return True

    # Check if HTTPS is missing
    if not link.lower().startswith("https://"):
        return True

    # Extract domain and check against database
    parts = tldextract.extract(link)
    if parts.subdomain.count('.') > 1:
        return True

    website = f"{parts.domain}.{parts.suffix}"
    if website in malicious_domains:
        return True

    return False

def main():
    bad_links = []
    good_links = []

    print("Enter URLs to scan, type 'done' when finished:")

    while True:
        url = input("URL: ").strip()
        if url.lower() == 'done':
            break
        if url == "":
            continue

        if check_link(url):
            bad_links.append(url)
        else:
            good_links.append(url)

    print("\nMALICIOUS URLs:")
    for url in bad_links:
        print(url)

    print("\nSAFE URLs:")
    for url in good_links:
        print(url)

if __name__ == "__main__":
    main()
