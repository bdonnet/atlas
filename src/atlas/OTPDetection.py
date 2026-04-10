"""
Looks for potential use of One-Time Password (OTP) or classic 2FA (non-FIDO2) on a webpage.

It is based on the following heuristics:
    - search for UI text mentioning OTP/2FA/MFA codes
    - Seach the DOM for relevant keywords
    - Inspect previously captured network requests (optional)
"""

from import_data import *

__all__ = ["detect_otp_indicators"]

OTP_REGEX = re.compile(r"\b(" + "|".join(re.escape(k) for k in OTP_KEYWORDS) + r")\b", re.IGNORECASE)

async def detect_otp_indicators(page: Page, requests_list: list | None = None) -> Dict[str, Any]:
    """
    Runs through a page for detecting potential use of OTP/classic 2FA

    Params:
        page: Playwright Page instance
        requests_list: optional list of network requests captured by setup_network_logging()

    Returns:
        Dictionary summarizing potential use of OTP
    """
    result = {
        "otp_ui_detected": False,
        "otp_dom_detected": False,
        "otp_network_detected": False,
        "otp_detected": False,
        "otp_signals": []
    }

    try:
        #1. Scan visible text
        visible_text = await page.inner_text()
        ui_matches = OTP_REGEX.findall(visible_text)
        if ui_matches:
            result["otp_ui_detected"] = True
            result["otp_signals"].extend(set(ui_matches))

        #2. Scan script and HTML source
        html_source = await page.evaluate("document.documentElement.innerHTML")
        dom_matches = OTP_REGEX.findall(html_source)
        if dom_matches:
            result["otp_dom_detected"] = True
            result["otp_signals"].extend(set(dom_matches))

        #3. Scan network requests (optional)
        if requests_list:
            net_matches = []
            for req in requests_list:
                if OTP_REGEX.search(req.url) or OTP_REGEX.search(req.method or ""):
                    net_matches.append(req.url)
            if net_matches:
                result["otp_network_detected"] = True
                result["otp_signals"].extend(net_matches)

        #4. Final decision
        result["otp_detected"] = any([
            result["otp_ui_detected"],
            result["otp_dom_detected"],
            result["otp_network_detected"]
        ])

    except Exception as e:
        result["error"] = f"OTP detection error: {e}"

    return result
