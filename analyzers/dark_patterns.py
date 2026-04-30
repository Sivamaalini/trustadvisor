import re
from bs4 import BeautifulSoup

# ── Text-based patterns ───────────────────────────────────────────────────────

URGENCY_PATTERNS = [
    r'\blimited time\b', r'\bact now\b', r'\bhurry\b', r'\bexpires?\b',
    r'\btoday only\b', r'\bends? (in|soon|tonight|at midnight)\b',
    r'\blast chance\b', r'\bdon\'?t miss\b', r'\bselling fast\b',
    r'\bflash sale\b', r'\b\d+\s*(hours?|minutes?|seconds?)\s*(left|remaining|only)\b',
    r'\bcountdown\b', r'\bdeadline\b', r'\burgent\b', r'\bimmediately\b',
]

SCARCITY_PATTERNS = [
    r'\bonly \d+ left\b', r'\b\d+ (remaining|in stock|available)\b',
    r'\blimited (stock|availability|supply|quantity|edition)\b',
    r'\bselling out\b', r'\balmost gone\b', r'\blast (item|one|few)\b',
    r'\blow stock\b', r'\bscarce\b', r'\brare\b.*\bavailable\b',
    r'\b\d+ people (are )?viewing\b', r'\b\d+ (others|people) (have )?(this in their|looking at)\b',
]

CONFIRM_SHAMING = [
    r'\bno thanks?,?\s+i\b', r'\bno,?\s+i don\'?t want\b',
    r'\bi (don\'?t|do not) (want|need|care about|deserve)\b',
    r'\bi\'?ll (pass|miss out|stay poor|stay unhealthy|remain)\b',
    r'\bno thanks?,?\s+i (prefer|like|want|love) (to )?(be )?',
    r'\bi\'?m (not|already)\b.*\binterested\b',
    r'\bno,?\s+i\'?m (fine|good|okay)\b',
]

SUBSCRIPTION_TRAP = [
    r'\bauto.?renew\b', r'\brecurring (charge|billing|payment)\b',
    r'\bsubscrib\w* (to|for)\b', r'\bcancell?\w* anytime\b',
    r'\bfree trial\b.*\bcard\b', r'\btrial.*\bautomatically\b',
    r'\bunsubscrib\w*\b.*\bdifficult\b', r'\bmonthly fee\b',
    r'\bannual (plan|subscription|billing)\b', r'\bsign up for free\b.*\blater\b',
]

HIDDEN_FEES = [
    r'\b(processing|handling|service|convenience|booking|admin|platform)\s+fee\b',
    r'\badditional charge\b', r'\bextra cost\b', r'\bnot included\b',
    r'\bsurcharge\b', r'\bfees? (apply|added|charged|at checkout)\b',
    r'\btaxes (not|extra)\b', r'\bshipping (not )?included\b.*\bcheckout\b',
    r'\bhidden (cost|fee|charge)\b', r'\bsee (full |all )?price at checkout\b',
]

FAKE_SOCIAL_PROOF = [
    r'\b\d+\s*(people|customers|users|shoppers)\s*(are )?(viewing|watching|bought|purchased)\b',
    r'\b\d+\s*(sold|purchases?)\s*(in|this|today|last)\b',
    r'\bmost popular\b', r'\bbest seller\b', r'\btop rated\b',
    r'\b#?1\s*(choice|pick|seller|rated)\b', r'\bcustomers? (love|trust)\b',
    r'\b\d+[,\d]*\s*(happy|satisfied|loyal)\s*customers?\b',
    r'\bverified (reviews?|buyers?|purchases?)\b',
]

MISLEADING_BUTTONS = [
    r'\bclose\b.*\bno thanks\b', r'\bskip\b.*\btrial\b',
    r'\bdownload\b.*\b(free|now)\b', r'\bclaim\b.*\b(offer|deal|gift|prize)\b',
    r'\bget started\b', r'\bcontinue\b.*\bfree\b',
    r'\byes,?\s+(give me|i want|send me|start my)\b',
]

ALL_TEXT_PATTERNS = {
    'Urgency Manipulation': URGENCY_PATTERNS,
    'Scarcity Manipulation': SCARCITY_PATTERNS,
    'Confirm-Shaming': CONFIRM_SHAMING,
    'Subscription Trap': SUBSCRIPTION_TRAP,
    'Hidden Fees Language': HIDDEN_FEES,
    'Fake Social Proof': FAKE_SOCIAL_PROOF,
    'Misleading Button Text': MISLEADING_BUTTONS,
}

# ── Weights per category ───────────────────────────────────────────────────────
CATEGORY_WEIGHTS = {
    'Urgency Manipulation': 8,
    'Scarcity Manipulation': 8,
    'Confirm-Shaming': 15,
    'Subscription Trap': 12,
    'Hidden Fees Language': 12,
    'Fake Social Proof': 6,
    'Misleading Button Text': 10,
    'Pre-Checked Checkboxes': 15,
    'Hidden Elements Detected': 5,
    'Popup/Overlay Detected': 8,
    'Forced Login Wall': 10,
    'Countdown Timer in DOM': 10,
    'Hidden Unsubscribe': 15,
    'Newsletter Forced Popup': 8,
}


def _scan_text(text: str) -> list:
    indicators = []
    text_lower = text.lower()
    for category, patterns in ALL_TEXT_PATTERNS.items():
        matches = []

        for pat in patterns:
           found = re.findall(pat, text_lower, re.IGNORECASE)
    for m in found[:2]:
        matches.append(str(m))
        if matches:
            indicators.append({
                'category': category,
                'type': 'text',
                'matches': list(set(str(m) for m in matches))[:3],
                'severity': 'high' if CATEGORY_WEIGHTS.get(category, 0) >= 12 else 'medium'
            })
    return indicators


def _scan_html(scraped: dict) -> list:
    indicators = []
    html = scraped.get('html', '')
    soup = scraped.get('soup') or BeautifulSoup(html, 'lxml')
    forms = scraped.get('forms', [])

    # Pre-checked checkboxes
    pre_checked = []
    for form in forms:
        for inp in form.get('inputs', []):
            if inp.get('type') == 'checkbox' and inp.get('checked'):
                pre_checked.append(inp.get('name', 'unnamed'))
    if pre_checked:
        indicators.append({
            'category': 'Pre-Checked Checkboxes',
            'type': 'html',
            'matches': pre_checked[:3],
            'severity': 'high'
        })

    # Hidden elements
    hidden = scraped.get('hidden_elements', [])
    if len(hidden) > 3:
        indicators.append({
            'category': 'Hidden Elements Detected',
            'type': 'html',
            'matches': [f'{len(hidden)} hidden elements found'],
            'severity': 'medium'
        })

    # Popup / modal overlays
    popup_classes = ['modal', 'popup', 'overlay', 'lightbox', 'dialog', 'interstitial', 'takeover']
    popup_found = []
    for cls in popup_classes:
        els = soup.find_all(class_=re.compile(cls, re.I))
        if els:
            popup_found.append(cls)
    if popup_found:
        indicators.append({
            'category': 'Popup/Overlay Detected',
            'type': 'html',
            'matches': popup_found[:3],
            'severity': 'medium'
        })

    # Forced login wall
    login_keywords = ['login to continue', 'sign in to view', 'create account to access',
                      'please log in', 'register to continue', 'members only']
    lw_found = [k for k in login_keywords if k in html.lower()]
    if lw_found:
        indicators.append({
            'category': 'Forced Login Wall',
            'type': 'html',
            'matches': lw_found[:2],
            'severity': 'high'
        })

    # Countdown timers
    timer_patterns = [r'countdown', r'timer', r'time-?left', r'expires?-?in', r'deal-?timer']
    timer_found = []
    for p in timer_patterns:
        if re.search(p, html, re.I):
            timer_found.append(p.replace('?', '').replace('-?', ''))
    if timer_found:
        indicators.append({
            'category': 'Countdown Timer in DOM',
            'type': 'html',
            'matches': list(set(timer_found))[:3],
            'severity': 'medium'
        })

    # Hidden unsubscribe
    unsub_hidden = re.findall(r'unsubscrib\w*', html, re.I)
    if unsub_hidden:
        for el in soup.find_all(string=re.compile(r'unsubscrib', re.I)):
            parent = el.parent
            if parent:
                style = parent.get('style', '').lower()
                if 'display:none' in style.replace(' ', '') or 'font-size:0' in style.replace(' ', '') or 'visibility:hidden' in style.replace(' ', ''):
                    indicators.append({
                        'category': 'Hidden Unsubscribe',
                        'type': 'html',
                        'matches': ['Unsubscribe link is hidden'],
                        'severity': 'high'
                    })
                    break

    # Newsletter forced popup
    nl_keywords = ['subscribe to our newsletter', 'sign up for emails', 'get our newsletter',
                   'email signup', 'join our mailing list']
    nl_found = [k for k in nl_keywords if k in html.lower()]
    if nl_found:
        indicators.append({
            'category': 'Newsletter Forced Popup',
            'type': 'html',
            'matches': nl_found[:2],
            'severity': 'medium'
        })

    return indicators


import math

def _calculate_score(indicators: list) -> float:
    if not indicators:
        return 0.0

    category_counts = {}

    for ind in indicators:
        cat = ind['category']
        weight = CATEGORY_WEIGHTS.get(cat, 5)
        category_counts[cat] = category_counts.get(cat, 0) + weight

    total = sum(category_counts.values())

    # smooth saturation (better than linear multiply)
    score = (total / (total + 12)) * 100

    return round(min(100, score), 1)

def analyze(scraped: dict) -> dict:
    text_indicators = _scan_text(scraped.get('text', ''))
    html_indicators = _scan_html(scraped)
    all_indicators = text_indicators + html_indicators

    category_counts = {}
    deduped = []

    # ── FIXED LOOP ─────────────────────────
    for ind in all_indicators:
        cat = ind.get('category', 'Other')   # safe default
        category_counts[cat] = category_counts.get(cat, 0) + 1
        deduped.append(ind)

    score = _calculate_score(deduped)

    return {
        "dark_pattern_score": score,
        "dark_indicators": deduped,
        "signal_counts": category_counts,
        "risk_level":
            "high" if score > 70 else
            "medium" if score > 40 else
            "low"
    }