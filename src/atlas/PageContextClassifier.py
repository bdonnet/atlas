"""
Classifies the type of page currently displayed before doing any authentication signals detection.

Many sites do NOT show the real page immediately:
    - anti-bot challenges (Cloudflare, Akamai, Datadome…)
    - CMP cookie walls (OneTrust, Quantcast, TrustArc…)
    - interstitial/splash pages
    - SSO redirects (Auth0, Okta, Microsoft, Google…)
    - app-promo modals
    - country/language selectors

This classifier is as generic as possible: it does not depend on any specific provider. It looks for patterns, not brands (said otherwise, pretty much
heuristic and may lead to false positives/negatives).

Returned structure example:
    {
        "page_type": "antibot_challenge",
        "blocked": True,
        "reason": "anti_bot_patterns",
        "details": {...},
        "recommended_action": None (by default)
    }

Page types:
    - antibot_challenge
    - cmp_blocking
    - interstitial
    - sso_provider
    - real_login_page
    - content_page
    - unknown
"""

from import_data import *

__all__ = ["classify_page_context", "detect_active_antibot"]

async def detect_active_antibot(network_requests):
    """
    Heuristically detects active anti-bot challenges that takes control of the
    flow once connected to the web site.
    """
    for req in network_requests:
        url = req.get("url", "")
        if "challenges.cloudflare.com" in url and "turnstile" in url:
            return True, "cloudflare_turnstile"
    return False, None

async def classify_page_context(page: Page) -> Dict[str, Any]:
    """
    Classifies a page

    Params:
        Page, the page to classify

    Returns:
        dictionary describing the page
    """

    title = (await page.title()) or ""
    url = page.url or ""

    # 1. Anti-bot
    anti = await _detect_antibot(page, url, title)
    if anti["match"]:
        return {
            "page_type": "antibot_challenge",
            "blocked": True,
            "reason": "anti_bot_patterns",
            "details": anti,
            "recommended_action": None
        }

    # 2. CMP / cookie wall
    cmp_res = await _detect_cmp_blocker(page)
    if cmp_res["match"]:
        return {
            "page_type": "cmp_blocking",
            "blocked": True,
            "reason": "cmp_fullscreen",
            "details": cmp_res,
            "recommended_action": None
        }

    # 3. Interstitial / splash
    inter = await _detect_interstitial(page)
    if inter["match"]:
        return {
            "page_type": "interstitial",
            "blocked": False,
            "reason": "interstitial_detected",
            "details": inter,
            "recommended_action": None
        }

    # 4. external SSO
    sso = _detect_sso_provider(url)
    if sso["match"]:
        return {
            "page_type": "sso_provider",
            "blocked": False,
            "reason": "external_login_domain",
            "details": sso,
            "recommended_action": None
        }

    # 5. real login page
    real = await _detect_real_login(page)
    if real["match"]:
        return {
            "page_type": "real_login_page",
            "blocked": False,
            "reason": "login_ui_detected",
            "details": real,
            "recommended_action": None
        }

    # 6. Generic content page
    return {
        "page_type": "content_page",
        "blocked": False,
        "reason": "no_special_patterns",
        "details": {},
        "recommended_action": None
    }

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

async def _detect_antibot(page: Page, url: str, title: str) -> Dict[str, Any]:
    """
    Tries to detect anti-bot pages with heuristics.

    Params:
        page, the page to analyse
        url, URL to the page
        title, page title

    Returns:
        dictionary with analysis results
    """
    patterns_url = [r"/cdn-cgi/challenge", r"/_sec/", r"/akamai/", r"/datadome", r"/bot-detection"]
    patterns_title = ["just a moment", "checking your browser", "verifying your connection", "attention required"]

    if any(re.search(p, url, re.IGNORECASE) for p in patterns_url):
        return {"match": True, "context": "url"}
    if any(p in title.lower() for p in patterns_title):
        return {"match": True, "context": "title"}
    return {"match": False}

async def _detect_cmp_blocker(page: Page) -> Dict[str, Any]:
    """
    Tries to detect CMP/visible cookie wall.

    Params:
        page, the page to analyse

    Returns:
        dictionary with analysis results
    """
    selectors = ["[id*='cookie']", "[id*='consent']", "[class*='cookie']", "[class*='consent']",
                 "[class*='gdpr']", "[role='dialog']", "[aria-modal='true']"]

    for sel in selectors:
        try:
            loc = page.locator(sel)
            count = await loc.count()
            for i in range(count):
                el = loc.nth(i)
                if await el.is_visible():
                    box = await el.bounding_box()
                    if box and box["height"] > 50:
                        return {"match": True, "selector": sel}
        except Exception:
            continue
    return {"match": False}

async def _detect_interstitial(page: Page) -> Dict[str, Any]:
    """
    Tries to detect splash or modal interstitial.

    Params:
        page, the page to analyse

    Returns:
        dictionary with analysis results
    """
    keywords = ["continue", "proceed", "enter site", "start reading"]
    for kw in keywords:
        try:
            loc = page.locator(f"text={kw}")
            count = await loc.count()
            for i in range(count):
                el = loc.nth(i)
                if await el.is_visible():
                    box = await el.bounding_box()
                    if box and box["height"] > 50:
                        return {"match": True, "keyword": kw}
        except Exception:
            continue
    return {"match": False}

def _detect_sso_provider(url: str) -> Dict[str, Any]:
    """
    Tries to determine wether the page comes from a known external SSO.

    Params:
        page, the page to analyse

    Returns:
        dictionary with analysis results
    """
    sso_domains = ["auth0.com", "okta.com", "login.microsoftonline.com",
                   "accounts.google.com", "appleid.apple.com", "secure.login.gov", "cognito.amazonaws.com"]
    for dom in sso_domains:
        if dom in url:
            return {"match": True, "domain": dom}
    return {"match": False}

async def _detect_real_login(page: Page) -> Dict[str, Any]:
    """
    Tries to detect whether the page is a real login one.

    Params:
        page, the page to analyse

    Returns:
        dictionary with analysis results
    """
    try:
        if await page.query_selector("input[type=password]"):
            return {"match": True, "detect": "password_field"}
        html = (await page.content()).lower()
        for kw in LOGIN_KEYWORDS:
            if kw in html:
                return {"match": True, "detect": "keyword", "keyword": kw}
    except Exception:
        pass
    return {"match": False}
