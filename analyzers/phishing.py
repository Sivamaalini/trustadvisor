import re
import tldextract
from urllib.parse import urlparse
from bs4 import BeautifulSoup

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club',
    '.online', '.site', '.website', '.space', '.tech', '.click',
    '.download', '.stream', '.gdn', '.icu', '.cyou', '.cam'
}

BRAND_IMPERSONATION = [
    'paypal', 'apple', 'google', 'amazon', 'microsoft', 'facebook', 'instagram',
    'netflix', 'bank', 'chase', 'wellsfargo', 'citibank', 'hsbc', 'barclays',
    'ebay', 'dropbox', 'linkedin', 'twitter', 'whatsapp', 'telegram',
    'coinbase', 'binance', 'crypto', 'wallet', 'signin', 'login', 'verify',
    'secure', 'account', 'update', 'confirm', 'support', 'helpdesk',
]

PHISHING_TEXT_PATTERNS = [
    r'\bverify your (account|identity|information|email|password)\b',
    r'\bsuspicious (activity|login|access)\b',
    r'\b(unusual|unauthorized) (activity|access|login)\b',
    r'\byour account (has been|will be) (suspended|locked|disabled|terminated)\b',
    r'\bclick here to (verify|confirm|restore|unlock)\b',
    r'\benter your (password|credentials|credit card|ssn|social security)\b',
    r'\bupdate your (payment|billing|account) (information|details)\b',
    r'\bwin (a |the )?(prize|lottery|gift|iphone|cash)\b',
    r'\byou have been selected\b', r'\bcongratulations? you (have )?won\b',
    r'\bact immediately\b.*\baccount\b',
    r'\bwe noticed\b.*\b(unusual|suspicious)\b',
    r'\bconfirm your identity\b', r'\bsecurity alert\b',
]

WEIGHTS = {
    'No HTTPS': 25,
    'Suspicious TLD': 20,
    'Excessive Subdomains': 15,
    'Brand Impersonation in URL': 20,
    'Login Form Detected': 10,
    'Hidden Iframes': 15,
    'High External Link Ratio': 10,
    'Multiple Redirects': 10,
    'Phishing Text Detected': 15,
    'IP Address as Host': 20,
    'Long URL': 8,
    'Multiple @ in URL': 20,
    'URL Mismatch (Anchor)': 15,
}


def analyze(scraped: dict) -> dict:
    url = scraped.get('url', '')
    html = scraped.get('html', '')
    text = scraped.get('text', '')
    links = scraped.get('links', [])
    soup = scraped.get('soup') or BeautifulSoup(html, 'lxml')

    indicators = []
    parsed = urlparse(url) if url else None
    ext = tldextract.extract(url) if url else None

    # 1. HTTPS check
    if parsed and parsed.scheme != 'https':
        indicators.append({
            'category': 'No HTTPS',
            'type': 'url',
            'matches': ['Site uses HTTP, not HTTPS'],
            'severity': 'high'
        })

    # 2. Suspicious TLD
    if ext:
        tld = '.' + ext.suffix.lower() if ext.suffix else ''
        if any(tld.endswith(s) for s in SUSPICIOUS_TLDS):
            indicators.append({
                'category': 'Suspicious TLD',
                'type': 'url',
                'matches': [f'TLD: {tld}'],
                'severity': 'high'
            })

    # 3. Excessive subdomains
    if parsed:
        host = parsed.hostname or ''
        parts = host.split('.')
        if len(parts) > 4:
            indicators.append({
                'category': 'Excessive Subdomains',
                'type': 'url',
                'matches': [f'{len(parts)-2} subdomains detected'],
                'severity': 'medium'
            })

    # 4. Brand impersonation
    if ext:
        domain_str = (ext.subdomain + '.' + ext.domain + '.' + ext.suffix).lower()
        impersonated = [b for b in BRAND_IMPERSONATION if b in domain_str]
        if impersonated and ext.domain not in impersonated:
            indicators.append({
                'category': 'Brand Impersonation in URL',
                'type': 'url',
                'matches': impersonated[:3],
                'severity': 'high'
            })

    # 5. Login forms
    login_inputs = ['password', 'passwd', 'pwd', 'pass']
    has_login = any(
        any(li in inp.get('name', '').lower() or li in inp.get('type', '').lower()
            for li in login_inputs)
        for form in scraped.get('forms', [])
        for inp in form.get('inputs', [])
    )
    if has_login:
        indicators.append({
            'category': 'Login Form Detected',
            'type': 'html',
            'matches': ['Password input field found'],
            'severity': 'medium'
        })

    # 6. Hidden iframes
    if html:
        iframes = soup.find_all('iframe')
        hidden_iframes = []
        for ifr in iframes:
            style = ifr.get('style', '').lower().replace(' ', '')
            if 'display:none' in style or 'visibility:hidden' in style or \
               ifr.get('width') == '0' or ifr.get('height') == '0':
                hidden_iframes.append(ifr.get('src', 'unknown src'))
        if hidden_iframes:
            indicators.append({
                'category': 'Hidden Iframes',
                'type': 'html',
                'matches': hidden_iframes[:2],
                'severity': 'high'
            })

    # 7. External link ratio
    if links and parsed:
        base_domain = (parsed.hostname or '').replace('www.', '')
        external = [l for l in links if l.startswith('http') and base_domain not in l]
        ratio = len(external) / len(links) if links else 0
        if ratio > 0.7 and len(links) > 10:
            indicators.append({
                'category': 'High External Link Ratio',
                'type': 'html',
                'matches': [f'{int(ratio*100)}% of links are external'],
                'severity': 'medium'
            })

    # 8. IP address as host
    if parsed:
        host = parsed.hostname or ''
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
            indicators.append({
                'category': 'IP Address as Host',
                'type': 'url',
                'matches': [f'Host is IP: {host}'],
                'severity': 'high'
            })

    # 9. Phishing text
    if text:
        text_lower = text.lower()
        phishing_matches = []
        for pat in PHISHING_TEXT_PATTERNS:
            found = re.findall(pat, text_lower, re.IGNORECASE)
            if found:
                phishing_matches.extend(found[:1])
        if phishing_matches:
            indicators.append({
                'category': 'Phishing Text Detected',
                'type': 'text',
                'matches': [str(m) for m in phishing_matches[:3]],
                'severity': 'high'
            })

    # 10. Long URL
    if url and len(url) > 100:
        indicators.append({
            'category': 'Long URL',
            'type': 'url',
            'matches': [f'URL length: {len(url)} characters'],
            'severity': 'low'
        })

    # 11. @ in URL
    if url and url.count('@') > 1:
        indicators.append({
            'category': 'Multiple @ in URL',
            'type': 'url',
            'matches': ['Multiple @ symbols detected'],
            'severity': 'high'
        })

    score = _calculate_score(indicators)
    return {
        'phishing_score': score,
        'phishing_indicators': indicators
    }


def _calculate_score(indicators: list) -> float:
    if not indicators:
        return 0.0
    total = sum(WEIGHTS.get(ind['category'], 5) for ind in indicators)
    return round(min(100, total * 1.5), 1)