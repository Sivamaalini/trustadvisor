import re
import logging

logger = logging.getLogger(__name__)

_model = None
_tokenizer = None
_model_loaded = False
_model_failed = False

HIGH_RISK_KEYWORDS = [
    'free money', 'guaranteed profit', 'no risk', 'make money fast',
    'get rich quick', 'million dollars', 'lottery winner', 'selected for prize',
    'bank account', 'wire transfer', 'social security', 'credit card number',
    'password reset required', 'immediate action required',
    'your computer is infected', 'call microsoft', 'irs notice',
    'unclaimed funds', 'inheritance', 'prince', 'confidential deal',
    'investment opportunity', 'double your money', 'binary options',
    'crypto guarantee', '100% returns', 'risk-free investment',
    'click here now', 'limited spots', 'not a scam', 'legitimate offer',
]

MEDIUM_RISK_KEYWORDS = [
    'exclusive offer', 'special promotion', 'act now',
    'apply now', 'no credit check', 'instant approval',
    'verify your account', 'update your details',
    'billing information', 'payment failed', 'account suspended',
    'final notice', 'overdue', 'debt collection',
    'cash advance', 'payday loan', 'quick cash',
]


def _load_model():
    global _model, _tokenizer, _model_loaded, _model_failed
    if _model_loaded or _model_failed:
        return
    try:
        from transformers import pipeline
        # Use a lightweight sentiment / text-classification model
        classifier = pipeline(
            'text-classification',
            model='distilbert-base-uncased-finetuned-sst-2-english',
            truncation=True,
            max_length=512
        )
        _model = classifier
        _model_loaded = True
        logger.info("AI model loaded successfully")
    except Exception as e:
        logger.warning(f"AI model load failed, using keyword fallback: {e}")
        _model_failed = True


def _keyword_analysis(text: str) -> dict:
    text_lower = text.lower()
    high_matches = [k for k in HIGH_RISK_KEYWORDS if k in text_lower]
    med_matches = [k for k in MEDIUM_RISK_KEYWORDS if k in text_lower]

    score = min(100, len(high_matches) * 15 + len(med_matches) * 7)
    all_matches = high_matches[:4] + med_matches[:3]

    return {
        'ai_risk_score': float(score),
        'ai_indicators': [{'category': 'High-Risk Language', 'matches': high_matches[:5], 'type': 'text', 'severity': 'high'}] if high_matches else
                         [{'category': 'Medium-Risk Language', 'matches': med_matches[:5], 'type': 'text', 'severity': 'medium'}] if med_matches else [],
        'method': 'keyword'
    }


def analyze(scraped: dict) -> dict:
    text = scraped.get('text', '')
    if not text or len(text) < 50:
        return {'ai_risk_score': 0.0, 'ai_indicators': [], 'method': 'none'}

    _load_model()

    if _model_loaded and _model:
        try:
            chunk = text[:512]
            result = _model(chunk)[0]
            label = result.get('label', 'POSITIVE')
            confidence = result.get('score', 0.5)

            # NEGATIVE label in SST-2 = negative/suspicious sentiment
            if label == 'NEGATIVE':
                base_score = confidence * 60
            else:
                base_score = (1 - confidence) * 30

            # Boost with keyword hits
            kw = _keyword_analysis(text)
            final_score = min(100, base_score + kw['ai_risk_score'] * 0.3)

            return {
                'ai_risk_score': round(final_score, 1),
                'ai_indicators': kw['ai_indicators'],
                'method': 'huggingface'
            }
        except Exception as e:
            logger.warning(f"AI inference failed: {e}")

    return _keyword_analysis(text)