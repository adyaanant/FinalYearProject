import io
import os
import re
import ssl
import socket
import requests
import tldextract
import cairosvg
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
from google.cloud import vision
from googleapiclient.discovery import build
from sklearn.feature_extraction.text import TfidfVectorizer
from playwright.sync_api import sync_playwright
import whois
import datetime
import hashlib
from bs4 import BeautifulSoup

app = Flask(__name__)

GOOGLE_SEARCH_API_KEY = ""
SEARCH_ENGINE_ID = ""
CUSTOMER_KEY = "adbdb3"
SHARED_CERTS = ["*.github.io", "*.wixsite.com", "*.netlify.app"]


# Helper Functions

def clean_text(text):
    print("in tf-idf")
    words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
    stopwords = {"www", "http", "https", "com", "html"}
    words = [word for word in words if word not in stopwords]
    if not words:
        return ""
    doc = [" ".join(words)]
    vectorizer = TfidfVectorizer(stop_words='english', max_features=10)
    tfidf_matrix = vectorizer.fit_transform(doc)
    feature_names = vectorizer.get_feature_names_out()
    return " ".join(feature_names)


def fetch_html(url):
    print("fetch_html")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    }
    parsed_url = urlparse(url)
    https_url = "https://" + parsed_url.netloc + parsed_url.path if parsed_url.scheme == "http" else url

    try:
        response = requests.get(https_url, headers=headers, timeout=100, allow_redirects=True)
        response.raise_for_status()
        if response.url.startswith("http://"):
            print(f"[WARNING] HTTPS downgraded to HTTP: {response.url}")
            return None, True
        return response.text, False
    except requests.exceptions.RequestException as e:
        print(f"[WARNING] Failed to load HTTPS: {e}")

    http_url = "http://" + parsed_url.netloc + parsed_url.path
    print(f"[INFO] Attempting to load HTTP version: {http_url}")
    try:
        response = requests.get(http_url, headers=headers, timeout=100, allow_redirects=True)
        response.raise_for_status()
        return response.text, False
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Could not fetch {http_url}: {e}")
        return None, False


def capture_screenshot(url, save_path="./screenshot.png"):
    print("\U0001F4F7 Capturing screenshot using Playwright (stealth)...")
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            page.goto(url, timeout=60000)
            page.set_viewport_size({"width": 1280, "height": 800})
            page.screenshot(path=save_path)
            browser.close()
        return save_path if os.path.exists(save_path) else None
    except Exception as e:
        print(f"❌ Playwright screenshot error: {e}")
        return None


def detect_text(image_path):
    print("perform ocr")
    client = vision.ImageAnnotatorClient()
    try:
        with open(image_path, "rb") as image_file:
            content = image_file.read()
        image = vision.Image(content=content)
        response = client.text_detection(image=image)
        texts = response.text_annotations

        if not texts or response.error.message:
            return [], []
        

        # First element is the full text block, skip it
        individual_texts = texts[1:]
        logo_texts = []
        other_texts = []

        for text in individual_texts:
            vertices = text.bounding_poly.vertices
            top = min(v.y for v in vertices)
            left = min(v.x for v in vertices)

            # Heuristic: consider top-left text (y < 200 and x < 300) as logo
            if top < 200 and left < 300:
                logo_texts.append(text.description)
            else:
                other_texts.append(text.description)

        return logo_texts, other_texts
    except Exception as e:
        print(f"❌ OCR Error: {e}")
        return [], []


def search_google(query):
    print(query)
    try:
        service = build("customsearch", "v1", developerKey=GOOGLE_SEARCH_API_KEY)
        result = service.cse().list(q=query, cx=SEARCH_ENGINE_ID).execute()
        return result.get("items", [])
    except Exception as e:
        print(f"Google Search Error: {e}")
        return []


def fetch_ssl_details(url):
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                certificate = ssock.getpeercert()
                return {
                    "issuer": dict(x[0] for x in certificate["issuer"]),
                    "subject": dict(x[0] for x in certificate["subject"]),
                    "valid_from": certificate.get("notBefore"),
                    "valid_to": certificate.get("notAfter"),
                }
    except Exception as e:
        print(f"[SSL ERROR] Failed to fetch cert for {url}: {e}")
        return None


def extract_root_domain(cn):
    cn = cn.replace("*.", "")
    ext = tldextract.extract(cn)
    return f"{ext.domain}.{ext.suffix}"


def compare_ssl(ssl1, ssl2):
    if not ssl1 or not ssl2:
        return False

    cn1 = ssl1.get("subject", {}).get("commonName", "")
    cn2 = ssl2.get("subject", {}).get("commonName", "")

    if cn1 in SHARED_CERTS or cn2 in SHARED_CERTS:
        print(f"[WARNING] Shared cert detected: {cn1} or {cn2}")
        return False

    root1 = extract_root_domain(cn1)
    root2 = extract_root_domain(cn2)

    print(f"[DEBUG] Comparing root domains: {root1} vs {root2}")

    return root1 == root2


def domain_age_check(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age_days = (datetime.datetime.now() - creation_date).days
        return age_days
    except:
        return 0
    
############

def extract_domain_tokens(url):
    ext = tldextract.extract(url)
    tokens = ext.domain.split('-') + ext.subdomain.split('.')
    return [token for token in tokens if token]

def extract_title(html):
    try:
        soup = BeautifulSoup(html, 'html.parser')
        title = soup.title.string if soup.title else ""
        return title.strip()
    except:
        return ""

def fetch_favicon_hash(url):
    try:
        parsed = urlparse(url)
        favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
        res = requests.get(favicon_url, timeout=5)
        if res.ok:
            return hashlib.md5(res.content).hexdigest()
    except:
        return None


@app.route('/detect', methods=['POST'])
def detect_phishing():
    data = request.json
    url = data.get("url", "")
    if not url:
        reason = "No URL provided"
        print(f"[DECISION] {reason}")
        return jsonify({"error": reason}), 400

    print(f"Processing URL: {url}")
    official_ssl = fetch_ssl_details(url)
    print(f"[SSL] Official SSL:\n{official_ssl}")

    if not official_ssl:
        reason = "No SSL certificate found"
        print(f"[DECISION] {reason}")
        return jsonify({"is_phishing": True, "reason": reason})

    # PHASE 1: Fast analysis
    html, downgrade_detected = fetch_html(url)
    if not html:
        reason = "Could not fetch HTML"
        print(f"[DECISION] {reason}")
        return jsonify({"is_phishing": True, "reason": reason})

    if downgrade_detected:
        reason = "HTTPS downgraded to HTTP"
        print(f"[DECISION] {reason}")
        return jsonify({"is_phishing": True, "reason": reason})

    domain_tokens = extract_domain_tokens(url)
    title_text = extract_title(html)
    target_favicon_hash = fetch_favicon_hash(url)

    search_query = title_text or " ".join(domain_tokens)
    search_results = search_google(search_query)

    match_found = False
    for result in search_results[:3]:
        result_ssl = fetch_ssl_details(result["link"])
        print(f"[SSL] Result SSL for {result['link']}:\n{result_ssl}")
        if compare_ssl(result_ssl, official_ssl):
            match_found = True
            break

        result_favicon = fetch_favicon_hash(result["link"])
        if target_favicon_hash and result_favicon and target_favicon_hash == result_favicon:
            print("[MATCH] Favicon matched")
            match_found = True
            break

    if match_found:
        #age = domain_age_check(url)
        #if age is None or age > 60:
        reason = "Matched official site via SSL or favicon"
        print(f"[DECISION] {reason}")
        return jsonify({"is_phishing": False, "reason": reason})
    else:
        print("[INFO] Proceeding to OCR phase.")

    # PHASE 2: Deep analysis
    screenshot_path = capture_screenshot(url)
    if not screenshot_path:
        reason = "Could not capture screenshot"
        print(f"[DECISION] {reason}")
        return jsonify({"is_phishing": True, "reason": reason})

    logo_texts, other_texts = detect_text(screenshot_path)

    print(f"[OCR] Logo Texts: {logo_texts}")
    print(f"[OCR] Other Texts: {other_texts}")

    # Weight logo texts 3x
    weighted_text = (" ".join(logo_texts) + " ") * 3 + " ".join(other_texts)
    query = clean_text(weighted_text)

    if not query:
        reason = "No readable text in images"
        print(f"[DECISION] {reason}")
        return jsonify({"is_phishing": True, "reason": reason})

    search_results = search_google(query)
    for result in search_results[:3]:
        result_ssl = fetch_ssl_details(result["link"])
        print(f"[SSL] OCR Result SSL for {result['link']}:\n{result_ssl}")
        if compare_ssl(result_ssl, official_ssl):
            reason = "SSL matches official site based on OCR text"
            print(f"[DECISION] {reason}")
            return jsonify({"is_phishing": False, "reason": reason})

    reason = "SSL does not match any official site"
    print(f"[DECISION] {reason}")
    return jsonify({"is_phishing": True, "reason": reason})

@app.route('/')
def home():
    return render_template('phishingUi.html')


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
