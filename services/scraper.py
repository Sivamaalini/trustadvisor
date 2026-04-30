import time
import random
import os
import logging
from urllib.parse import urlparse
from screenshot_engine import analyze_and_screenshot

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
]

SCREENSHOT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'screenshots')
os.makedirs(SCREENSHOT_DIR, exist_ok=True)


def _get_headers():
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Cache-Control': 'max-age=0',
    }


def _try_selenium(url: str) -> dict:
    """Attempt scraping via Selenium with stealth settings."""
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.webdriver.common.by import By
        from selenium.webdriver.common.action_chains import ActionChains
        from webdriver_manager.chrome import ChromeDriverManager

        opts = Options()
        opts.add_argument('--headless=new')
        opts.add_argument('--no-sandbox')
        opts.add_argument('--disable-dev-shm-usage')
        opts.add_argument('--disable-gpu')
        opts.add_argument('--window-size=1280,900')
        opts.add_argument(f'--user-agent={random.choice(USER_AGENTS)}')
        opts.add_argument('--disable-blink-features=AutomationControlled')
        opts.add_experimental_option('excludeSwitches', ['enable-automation'])
        opts.add_experimental_option('useAutomationExtension', False)
        opts.add_argument('--disable-extensions')
        opts.add_argument('--disable-infobars')
        opts.add_argument('--lang=en-US')

        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=opts)
        driver.execute_cdp_cmd('Network.setUserAgentOverride', {'userAgent': random.choice(USER_AGENTS)})
        driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")

        driver.set_page_load_timeout(20)
        driver.get(url)

        # Scroll slowly
        for _ in range(4):
            driver.execute_script("window.scrollBy(0, window.innerHeight * 0.4);")
            time.sleep(0.4)
        driver.execute_script("window.scrollTo(0, 0);")
        time.sleep(1)

        # Screenshot
        screenshot_path = ''
        try:
            fname = f"screen_{int(time.time())}_{random.randint(1000,9999)}.png"
            screenshot_path = os.path.join(SCREENSHOT_DIR, fname)
            driver.save_screenshot(screenshot_path)
        except Exception:
            pass

        html = driver.page_source
        driver.quit()

        return {'html': html, 'screenshot_path': screenshot_path, 'method': 'selenium', 'status': 'ok'}

    except Exception as e:
        logger.warning(f"Selenium failed: {e}")
        return {}


def _try_requests(url: str) -> dict:
    """Fallback scraper using requests."""
    try:
        session = requests.Session()
        session.headers.update(_get_headers())
        resp = session.get(url, timeout=15, allow_redirects=True, verify=False)
        resp.raise_for_status()
        return {'html': resp.text, 'screenshot_path': '', 'method': 'requests', 'status': 'ok'}
    except Exception as e:
        logger.warning(f"Requests fallback failed: {e}")
        return {}


def scrape(url: str) -> dict:
    """
    Main scrape entry point. Tries Selenium, falls back to requests.
    Always takes a Playwright screenshot and returns it.
    Never crashes — always returns a dict.
    """
    from screenshot_engine import analyze_and_screenshot

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # ── 1) Try scraping page content ─────────────────────────
    result = _try_selenium(url)
    if not result:
        result = _try_requests(url)

    # ── 2) ALWAYS take screenshot (independent of scraping) ───
    try:
        shot = analyze_and_screenshot(url)
        screenshot_path = shot.get("screenshot", "")
        print("[SCRAPER] Screenshot path:", screenshot_path)
    except Exception as e:
        print("[SCRAPER] Screenshot failed:", e)
        screenshot_path = ""

    # ── 3) If scraping failed completely ─────────────────────
    if not result:
        return {
            'html': '',
            'text': '',
            'forms': [],
            'buttons': [],
            'links': [],
            'hidden_elements': [],
            'screenshot_path': f"static/{screenshot_path}" if screenshot_path else "",
            'method': 'none',
            'status': 'partial_analysis',
            'status_message': 'Website blocked automated analysis or is unreachable.',
            'url': url
        }

    # ── 4) Parse HTML properly ───────────────────────────────
    html = result.get('html', '')
    soup = BeautifulSoup(html, 'lxml') if html else BeautifulSoup('', 'lxml')

    for tag in soup(['script', 'style', 'noscript', 'meta', 'head']):
        tag.decompose()

    text = ' '.join(soup.get_text(separator=' ').split())

    forms = []
    for form in soup.find_all('form'):
        inputs = [
            {'type': i.get('type', 'text'),
             'name': i.get('name', ''),
             'checked': i.get('checked') is not None}
            for i in form.find_all('input')
        ]
        forms.append({'action': form.get('action', ''), 'method': form.get('method', 'get'), 'inputs': inputs})

    buttons = [b.get_text(strip=True) for b in soup.find_all(['button', 'input'])
               if b.get('type') in (None, 'submit', 'button')]

    links = [a.get('href', '') for a in soup.find_all('a', href=True)]

    hidden = []
    for el in soup.find_all(style=True):
        style = el.get('style', '').lower().replace(" ", "")
        if 'display:none' in style or 'visibility:hidden' in style or 'opacity:0' in style:
            hidden.append(el.get_text(strip=True)[:100])

    # ── 5) FINAL RETURN (THIS WAS THE MISSING LINK) ───────────
    return {
        'html': html,
        'text': text[:50000],
        'forms': forms,
        'buttons': buttons,
        'links': links,
        'hidden_elements': hidden,
        'screenshot_path': f"static/{screenshot_path}" if screenshot_path else "",
        'method': result.get('method', 'unknown'),
        'status': result.get('status', 'ok'),
        'status_message': '',
        'url': url,
        'soup': soup
    }


def scrape_html_file(html_content: str, url: str = 'demo') -> dict: 
    from screenshot_engine import analyze_and_screenshot

    try:
         shot = analyze_and_screenshot(url, html_content=html_content)
         screenshot_path = f"static/{shot.get('screenshot','')}"
         print("[DEMO] Screenshot path:", screenshot_path)
    except Exception as e:
      print("[DEMO] Screenshot failed:", e)
    screenshot_path = ""
    """Scrape from raw HTML string (used for demo mode)."""
    soup = BeautifulSoup(html_content, 'lxml')

    for tag in soup(['script', 'style', 'noscript', 'meta', 'head']):
        tag.decompose()
    text = ' '.join(soup.get_text(separator=' ').split())

    forms = []
    for form in soup.find_all('form'):
        inputs = [{'type': i.get('type', 'text'), 'name': i.get('name', ''), 'checked': i.get('checked') is not None}
                  for i in form.find_all('input')]
        forms.append({'action': form.get('action', ''), 'method': form.get('method', 'get'), 'inputs': inputs})

    buttons = [b.get_text(strip=True) for b in soup.find_all(['button', 'input'])]
    links = [a.get('href', '') for a in soup.find_all('a', href=True)]

    hidden = []
    for el in soup.find_all(style=True):
        style = el.get('style', '').lower()
        if 'display:none' in style.replace(' ', '') or 'opacity:0' in style.replace(' ', ''):
            hidden.append(el.get_text(strip=True)[:100])

    return {
        'html': html_content,
        'text': text[:50000],
        'forms': forms,
        'buttons': buttons,
        'links': links,
        'hidden_elements': hidden,
        'screenshot_path': f"static/{screenshot_path}" if screenshot_path else "",
        'method': 'demo',
        'status': 'ok',
        'status_message': '',
        'url': url,
        'soup': soup
    }