"""
PhishGuard Local AI Security Analyst

No external API.
No API key.
No internet connection required.

This agent interprets the existing ML scan result and
generates a human-readable cybersecurity analysis.
"""

import re


def _risk_advice(risk_score):
    if risk_score >= 80:
        return (
            "This URL should be treated as highly risky. "
            "Do not enter passwords, OTPs, banking details, or other sensitive information."
        )

    if risk_score >= 61:
        return (
            "This URL has a high level of risk. "
            "Avoid entering credentials or personal information until the website "
            "has been independently verified."
        )

    if risk_score >= 31:
        return (
            "This URL has some suspicious characteristics. "
            "Proceed carefully and verify the website before entering sensitive information."
        )

    return (
        "The URL has relatively few suspicious characteristics. "
        "However, static URL analysis cannot guarantee that a website is completely safe."
    )


def _explain_prediction(prediction):
    prediction = str(prediction).lower()

    if "phishing" in prediction or "malicious" in prediction:
        return (
            "The machine-learning model classified this URL as potentially "
            "phishing or malicious."
        )

    if "suspicious" in prediction:
        return (
            "The machine-learning model identified characteristics that "
            "make this URL suspicious."
        )

    return (
        "The machine-learning model did not identify enough strong phishing "
        "indicators to classify this URL as malicious."
    )


def _format_reasons(reasons):
    if not reasons:
        return "No major suspicious indicators were recorded."

    formatted = []

    for reason in reasons:
        text = str(reason).strip()

        if not text:
            continue

        formatted.append(f"- {text}")

    if not formatted:
        return "No major suspicious indicators were recorded."

    return "\n".join(formatted)


def _feature_analysis(features):
    if not isinstance(features, dict):
        return []

    observations = []

    # URL length
    length = features.get("url_length")

    if isinstance(length, (int, float)):
        if length > 100:
            observations.append(
                "The URL is unusually long, which can sometimes be used "
                "to hide suspicious paths or parameters."
            )

    # HTTPS
    https = features.get("has_https")

    if https in [0, False, "0"]:
        observations.append(
            "The URL does not use HTTPS. Sensitive information should not "
            "be entered into an unencrypted connection."
        )

    # IP address
    ip = features.get("has_ip")

    if ip in [1, True, "1"]:
        observations.append(
            "The URL appears to use an IP address instead of a normal domain name."
        )

    # @ symbol
    at_symbol = features.get("has_at")

    if at_symbol in [1, True, "1"]:
        observations.append(
            "The URL contains an '@' symbol, which can be associated with "
            "misleading URL structures."
        )

    # subdomains
    subdomains = features.get("subdomain_count")

    if isinstance(subdomains, (int, float)) and subdomains >= 3:
        observations.append(
            "The URL contains multiple subdomains, which may deserve additional scrutiny."
        )

    # query parameters
    query_params = features.get("query_params")

    if isinstance(query_params, (int, float)) and query_params >= 4:
        observations.append(
            "The URL contains several query parameters."
        )

    return observations


def build_scan_analysis(scan_data):
    if not isinstance(scan_data, dict):
        scan_data = {}

    url = scan_data.get("url", "Unknown URL")
    prediction = scan_data.get("prediction", "Unknown")
    risk_score = scan_data.get("risk_score", 0)
    risk_level = scan_data.get("risk_level", "Unknown")
    confidence = scan_data.get("confidence", 0)

    reasons = scan_data.get("reasons", [])
    features = scan_data.get("features", {})

    try:
        risk_score = float(risk_score)
    except (ValueError, TypeError):
        risk_score = 0

    try:
        confidence = float(confidence)
    except (ValueError, TypeError):
        confidence = 0

    explanation = _explain_prediction(prediction)

    advice = _risk_advice(risk_score)

    reason_text = _format_reasons(reasons)

    feature_observations = _feature_analysis(features)

    if feature_observations:
        feature_text = "\n".join(
            f"- {item}" for item in feature_observations
        )
    else:
        feature_text = "- No additional feature-level observations."

    analysis = f"""
PhishGuard Security Analyst
===========================

URL:
{url}

Classification:
{prediction}

Risk Score:
{risk_score:.0f}/100

Risk Level:
{risk_level}

Model Confidence:
{confidence:.2f}%

What this means:
{explanation}

Why the URL was flagged:
{reason_text}

Additional analysis:
{feature_text}

Recommended action:
{advice}

Important:
This analysis is based on static URL characteristics and the PhishGuard
machine-learning model. It does not visit or inspect the website itself.
A low-risk result does not guarantee that a website is completely safe.
"""

    return analysis.strip()


def ask_agent(question, scan_data):
    # Dangerous characteristics
    if (
            "dangerous" in question
            or "make" in question and "danger" in question
    ):
        reasons = scan_data.get("reasons", [])

        return f"""
    What Makes This URL Risky?
    ==========================

    The model identified the following characteristics:

    {_format_reasons(reasons)}

    These indicators contribute to the overall risk assessment.

    Remember: the analysis is based only on the URL itself.
    PhishGuard does not visit or execute the website.
    """.strip()

    # Safe verification
    if (
            "verify" in question
            or "verification" in question
    ):
        return """
    How to Verify a URL Safely
    ==========================

    1. Check the spelling of the domain carefully.
    2. Do not trust shortened or unexpected links.
    3. Navigate to the organization's official website manually.
    4. Compare the domain with the official domain.
    5. Do not enter passwords or OTPs on suspicious pages.
    6. Be especially careful with links received through unknown
       emails, messages, or social media.

    PhishGuard performs static URL analysis and does not visit
    the website to verify its actual contents.
    """.strip()
    """
    Local rule-based security analyst.

    No OpenAI API is used.
    """

    question = str(question or "").strip().lower()

    if not question:
        return "Please enter a security question."

    # Main explanation
    if (
        "why" in question
        or "flag" in question
        or "phishing" in question
        or "suspicious" in question
    ):
        return build_scan_analysis(scan_data)

    # Risk question
    if (
        "risk" in question
        or "score" in question
        or "danger" in question
    ):
        risk_score = scan_data.get("risk_score", 0)

        try:
            risk_score = float(risk_score)
        except (ValueError, TypeError):
            risk_score = 0

        return f"""
Risk Score Analysis
===================

The URL received a risk score of {risk_score:.0f}/100.

{_risk_advice(risk_score)}

The score is calculated from URL characteristics and the
machine-learning model. It should be treated as a risk indicator,
not as a guarantee of safety or maliciousness.
""".strip()

    # Action question
    if (
        "what should" in question
        or "what do" in question
        or "action" in question
        or "safe" in question
        or "click" in question
    ):
        risk_score = scan_data.get("risk_score", 0)

        try:
            risk_score = float(risk_score)
        except (ValueError, TypeError):
            risk_score = 0

        if risk_score >= 61:
            return """
Recommended Action
==================

1. Do not open the suspicious website.
2. Do not enter your password or OTP.
3. Do not provide banking or payment information.
4. Verify the domain using an independently trusted source.
5. If the link came through email or a message, verify the sender.
6. If credentials were already entered, change the password immediately
   using the official website or application.
""".strip()

        if risk_score >= 31:
            return """
Recommended Action
==================

1. Verify the domain carefully.
2. Check the spelling of the website name.
3. Avoid entering sensitive information until verified.
4. Prefer accessing the organization through its official website
   instead of using an unknown link.
""".strip()

        return """
Recommended Action
==================

The URL currently has a relatively low risk score.

Still:

1. Verify the domain.
2. Avoid entering sensitive information on unfamiliar websites.
3. Do not assume that a low score guarantees safety.
""".strip()

    # Confidence question
    if "confidence" in question:
        confidence = scan_data.get("confidence", 0)

        return f"""
Model Confidence
================

The model reported a confidence of {confidence}%.

This represents the model's confidence in its classification based
on the URL features it received. It is NOT a guarantee that the
website is actually safe or malicious.
""".strip()

    # Feature question
    if (
        "feature" in question
        or "indicator" in question
        or "characteristic" in question
    ):
        return build_scan_analysis(scan_data)

    # Generic response
    return f"""
PhishGuard Local Security Analyst
=================================

I can analyze the current scan using the information generated by
the PhishGuard machine-learning model.

I can explain:

• Why the URL was flagged
• The risk score
• Model confidence
• Suspicious indicators
• URL features
• Recommended actions

Try asking:

"Why was this URL flagged?"

"Explain the risk score."

"What should I do?"

"Which features are suspicious?"
""".strip()


def analyze_scan(scan_data):
    return build_scan_analysis(scan_data)