"""
Manages cookie acceptation
"""

from import_data import *

__all__ = ["accept_cookie_banner", "handle_consent_banners", "handle_language_selector", "handle_locale_suggestion"]

async def handle_consent_banners(page):
    """
    Manages potential cookie consent banner hidden in iFrame (important for European website).

    Params:
        page: Playwright Page object to scrap
    """
    try:
        accepted = None
        iframes = await asyncio.wait_for(_detect_consent_iframe(page), 1500)
        for frame in iframes:
            accepted = await _accept_cookie_banner_in_iframe(frame)
        if accepted:
            logger.info("[Cookie iFrame] Consentement accepté via iframe")
            return True
    except asyncio.TimeoutError:
        logger.debug('Timeout occurred after waiting for 100 seconds')
        return False

    return False

async def handle_locale_suggestion(page) -> bool:
    """
    Attempts to dismiss a locale/language/currency suggestion modal
    by clicking the negative / keep-current-preferences option.

    Returns True if a click was performed.
    """
    try:
        buttons = await page.query_selector_all("button")

        for btn in buttons:
            try:
                text = (await btn.inner_text()).lower().strip()
            except:
                continue

            if any(hint in text for hint in NEGATIVE_ACTION_HINTS):
                box = await btn.bounding_box()
                if not box:
                    continue

                # Avoid tiny / hidden buttons
                if box["width"] < 60 or box["height"] < 25:
                    continue

                await btn.click()
                if hasattr(page, '_fidology_results'):
                    page._fidology_results["nb_clicks"] = page._fidology_results.get("nb_clicks", 0) + 1
                await asyncio.sleep(1)
                return True

    except Exception:
        pass

    return False

async def handle_language_selector(page, timeout=3200) -> bool:
    """
    Attempts to dismiss a language selection modal if present.
    Returns True if a click was performed.
    """
    try:
        # Find visible buttons
        buttons = await page.query_selector_all("button, a, [role='button']")

        for btn in buttons:
            try:
                text = (await btn.inner_text()).lower().strip()
            except:
                continue

            if any(hint in text for hint in LANGUAGE_HINTS):
                box = await btn.bounding_box()
                if box and box["width"] > 40 and box["height"] > 20:
                    await btn.click(timeout=timeout)
                    if hasattr(page, '_fidology_results'):
                        page._fidology_results["nb_clicks"] = page._fidology_results.get("nb_clicks", 0) + 1
                    await asyncio.sleep(1)
                    return True

    except Exception:
        pass

    return False

async def accept_cookie_banner(page: Page, timeout_ms: int = TIMEOUT_COOKIE) -> bool:
    """
    Best-effort attempt to accept cookie banners.
    Non-blocking: never exceeds timeout_ms globally.
    """

    start = asyncio.get_event_loop().time()
    deadline = start + (timeout_ms / 1000)

    while asyncio.get_event_loop().time() < deadline:
        for selector in COOKIE_BANNER_SELECTOR:
            try:
                button = await page.query_selector(selector)
                if not button:
                    continue

                # Ensure button is visible and enabled
                if await button.is_visible(timeout=2000):
                    await button.click(timeout=2000)
                    if hasattr(page, '_fidology_results'):
                        page._fidology_results["nb_clicks"] = page._fidology_results.get("nb_clicks", 0) + 1
                    logger.info(f"[cookie-banner] Found and clicked: {selector}")
                    return True

            except Exception as e:
                logger.debug(f"[cookie-banner] Selector failed {selector}: {e}")

        # Short sleep to allow late-rendered banners
        await asyncio.sleep(0.2)

    logger.info("[cookie-banner] No cookie banner detected (best-effort).")
    return False

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

async def _detect_consent_iframe(page):
    """
    Runs through iFrames of a given page for consent management.

    Params:
        page: Playwright Page object to run through

    Results:
        a list of iFrames containing a cookie banner.
    """
    consent_iframes = []

    for frame in page.frames:
        try:
            content = await frame.content()
            if any(keyword in content.lower() for keyword in CONSENT_KEYWORDS):
                consent_iframes.append(frame)
        except Exception:
            continue

    return consent_iframes

async def _accept_cookie_banner_in_iframe(frame):
    """
    Looks for consent selectors in a given iFrame.

    Params:
        frame, the iFrame to check

    Results:
        True if a button has been found and clicked.  False otherwise.
    """
    for selector in CONSENT_SELECTORS:
        try:
            button = await frame.query_selector(selector)
            if button:
                await button.click()
                if hasattr(page, '_fidology_results'):
                    page._fidology_results["nb_clicks"] = page._fidology_results.get("nb_clicks", 0) + 1
                return True
        except Exception:
            continue
    return False
