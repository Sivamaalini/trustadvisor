def compute(dark_pattern_score: float, phishing_score: float, ai_risk_score: float) -> dict:
    """
    Weighted scoring:
      Dark Patterns → 60%
      Phishing      → 30%
      AI Risk       → 10%
    """
    total_score = (
        dark_pattern_score * 0.60 +
        phishing_score * 0.30 +
        ai_risk_score * 0.10
    )
    total_score = round(min(100.0, total_score), 1)

    if total_score < 40:
        risk_level = 'LOW'
        verdict = 'SAFE'
        verdict_label = '✅ Safe to Use'
        verdict_message = (
            "This website appears safe to use. Our analysis found minimal dark patterns and no significant "
            "phishing indicators. Always exercise standard online caution."
        )
        verdict_color = 'green'
    elif total_score < 70:
        risk_level = 'MEDIUM'
        verdict = 'CAUTION'
        verdict_label = '⚠️ Be Careful'
        verdict_message = (
            "This website shows some concerning patterns. Proceed with caution — review any agreements carefully, "
            "avoid sharing sensitive personal information, and watch for hidden charges or manipulative UI."
        )
        verdict_color = 'orange'
    else:
        risk_level = 'HIGH'
        verdict = 'AVOID'
        verdict_label = '❌ Avoid This Website'
        verdict_message = (
            "This website displays multiple high-risk indicators including dark patterns and possible phishing techniques. "
            "We strongly recommend avoiding this site and not entering any personal or payment information."
        )
        verdict_color = 'red'

    return {
        'total_score': total_score,
        'risk_level': risk_level,
        'verdict': verdict,
        'verdict_label': verdict_label,
        'verdict_message': verdict_message,
        'verdict_color': verdict_color,
    }