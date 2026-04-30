def respond(question: str, result: dict) -> str:
    """
    Rule-based chatbot that explains the scan results in simple language.
    """

    if not result:
        return "Please run a website scan first so I can explain the results."

    q = question.lower()

    risk = result.get("risk_level", "UNKNOWN")
    dark_score = result.get("dark_pattern_score", 0)
    phishing_score = result.get("phishing_score", 0)
    verdict_msg = result.get("verdict_message", "")

    if "safe" in q or "trust" in q:
        return verdict_msg

    if "dark" in q:
        return (
            f"The Dark Pattern Score is {dark_score}/100.\n"
            "Higher values indicate manipulative UI techniques such as urgency tactics, hidden fees, or forced sign-ups."
        )

    if "phishing" in q or "scam" in q:
        return (
            f"The Phishing Score is {phishing_score}/100.\n"
            "Higher values indicate suspicious domain behavior, login traps, or deceptive links."
        )

    if "risk" in q or "score" in q:
        return f"The overall website risk level is {risk}. {verdict_msg}"

    return (
        "You can ask me things like:\n"
        "• Is this website safe?\n"
        "• Why is the risk high?\n"
        "• What dark patterns were found?\n"
        "• What is the phishing risk?"
    )