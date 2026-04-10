"""
Allows to detect the presence of multi-steps login.  It manages successive clicks (e.g., email field first, password next).
"""

from import_data import *

__all__ = ["detect_multistep_login"]

async def detect_multistep_login(page: Page, required_steps: int = 2) -> bool:
    """
    Detects multistep login by attempting generic selectors.

    Improvements:
        - Uses robust handle_multistep_login()
        - Can adjust threshold of required steps

    Params:
        page: the page to investigate
        required_steps: minimum steps to consider multistep login detected

    Returns:
        True if at least required_steps were completed
    """
    try:
        steps_completed = await _handle_multistep_login(page, STEP_SELECTORS)
    except Exception:
        steps_completed = 0
        pass
    logger.info(f"Multi-step login detection: {steps_completed} steps completed")
    return steps_completed >= required_steps

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

async def _click_exact_button(page: Page, selector: str, timeout: int = 700) -> bool:
    """
    Click helper that resolves ambiguous locators in strict mode.

    Playwright raises a strict-mode error when a locator resolves to more than
    one element.
    This function applies the following heuristics (applied in order) for
    clicking on the "exact" button:
      1. If locator.count() == 0 -> nothing to click -> return False.
      2. If locator.count() == 1 -> safe to click directly.
      3. Otherwise (multiple matches):
         a) filter candidates to those that are visible AND enabled AND non-
         zero size
         b) if exactly one candidate remains -> click it
         c) try to extract the textual intent from the selector (e.g.
         "Continue" from "button:has-text('Continue')")
            and prefer candidates whose visible text or aria-label contains
            that intent
            — if several match, prefer the candidate with the longest visible
            text (heuristic: more descriptive)
         d) deprioritize elements with IDs/classes indicating ads/modals (heuristic blacklist)
         e) as a last resort, click the first visible candidate (best-effort)

    The helper never raises Playwright strict-mode errors; it logs decisions for debugging.

    Params:
        page: Playwright Page
        selector: the selector string (see STEP_SELECTORS) already used by the code (e.g. "button:has-text('Continue')")
        timeout: how long to wait for the selector to appear (ms)

    Returns:
        True if a click was performed, False otherwise.
    """

    try:
        locator = page.locator(selector)
    except Exception as e:
        logger.debug(f"click_exact_button: invalid selector '{selector}': {e}")
        return False

    # 1. wait up to `timeout` for at least one match to appear
    try:
        await page.wait_for_selector(selector, state="visible", timeout=timeout)
    except PlaywrightTimeoutError:
        logger.debug(f"click_exact_button: no element visible for selector '{selector}' within {timeout}ms")
        return False
    except Exception as e:
        logger.debug(f"click_exact_button: wait_for_selector error for '{selector}': {e}")
        # fall through to try counting anyway

    # 2. count matches
    try:
        count = await locator.count()
    except Exception as e:
        logger.debug(f"click_exact_button: locator.count() failed for '{selector}': {e}")
        count = 0

    if count == 0:
        logger.debug(f"click_exact_button: no matches for '{selector}'")
        return False

    # If unique match -> click it
    if count == 1:
        try:
            await locator.first.click()
            if hasattr(page, '_fidology_results'):
                page._fidology_results["nb_clicks"] = page._fidology_results.get("nb_clicks", 0) + 1
            logger.info(f"click_exact_button: clicked unique match for '{selector}'")
            return True
        except Exception as e:
            logger.error(f"click_exact_button: error clicking unique match for '{selector}': {e}")
            return False

    # 3. multiple matches: collect candidate metadata
    candidates = []
    for i in range(count):
        try:
            el = locator.nth(i)
            is_vis = await el.is_visible()
            is_en = await el.is_enabled()
            bbox = await el.bounding_box()  # None if not actionable/zero-size
            text = (await el.inner_text()) or ""
            aria = (await el.get_attribute("aria-label")) or ""
            elem_id = (await el.get_attribute("id")) or ""
            elem_class = (await el.get_attribute("class")) or ""

            # candidate passes basic checks
            if not is_vis or not is_en:
                continue
            if bbox is None or (bbox.get("width", 0) == 0 and bbox.get("height", 0) == 0):
                continue

            candidates.append({"index": i, "el": el, "text": text.strip(), "aria": aria.strip(), "id": elem_id.strip(), "class": elem_class.strip(), "bbox": bbox})
        except Exception:
            # ignore problematic candidate
            continue

    if not candidates:
        logger.debug(f"click_exact_button: no visible/enabled candidates for '{selector}'")
        return False

    # 4. Try to extract target text intent from selector (e.g. has-text('Continue') => "Continue")
    search_text = None
    try:
        # capture text inside has-text('...') or text="..."
        m = re.search(r"has-text\\(['\\\"](.+?)['\\\"]\\)", selector)
        if not m:
            m = re.search(r"text=([\"'])(.+?)\\1", selector)
        if m:
            # group may differ depending on which regex matched
            search_text = m.group(1) if m.lastindex == 1 else m.group(2)
            if isinstance(search_text, str):
                search_text = search_text.strip().lower()
    except Exception:
        search_text = None

    # 5. If we have search_text, prefer candidates whose text or aria contains it.
    preferred = []
    if search_text:
        for c in candidates:
            txt = (c["text"] or "").lower()
            aria = (c["aria"] or "").lower()
            if search_text in txt or search_text in aria:
                preferred.append(c)

    # 6. If multiple preferred, pick the one with the longest visible text (heuristic: more descriptive)
    chosen = None
    if preferred:
        preferred.sort(key=lambda c: len(c["text"] or c["aria"] or ""), reverse=True)
        chosen = preferred[0]
        logger.debug(f"click_exact_button: disambiguated by text match for '{selector}', chose candidate index {chosen['index']}")

    # 7. Heuristic blacklist: deprioritize ad/modal-like IDs/classes (if still ambiguous)
    if not chosen and len(candidates) > 1:
        blacklist_tokens = ["ad", "advert", "adchoices", "cookie", "interstitial", "modal", "promo", "close-interstitial"]
        non_blacklist = []
        for c in candidates:
            combined = " ".join([c["id"].lower(), c["class"].lower(), c["text"].lower()])
            if any(token in combined for token in blacklist_tokens):
                logger.debug(f"click_exact_button: deprioritizing candidate index {c['index']} due to blacklist token")
                continue
            non_blacklist.append(c)
        if len(non_blacklist) == 1:
            chosen = non_blacklist[0]
            logger.debug(f"click_exact_button: chose non-blacklist candidate index {chosen['index']}")
        elif len(non_blacklist) > 1:
            # fallback to longer text heuristic among non-blacklisted
            non_blacklist.sort(key=lambda c: len(c["text"] or c["aria"] or ""), reverse=True)
            chosen = non_blacklist[0]
            logger.debug(f"click_exact_button: multiple non-blacklist candidates, chose index {chosen['index']}")

    # 8. Final fallback: pick first candidate
    if not chosen:
        chosen = candidates[0]
        logger.debug(f"click_exact_button: fallback chosen index {chosen['index']} for '{selector}'")

    # 9. Attempt click on chosen candidate, with defensive try/except
    try:
        await chosen["el"].click()
        if hasattr(page, '_fidology_results'):
            page._fidology_results["nb_clicks"] = page._fidology_results.get("nb_clicks", 0) + 1
        logger.info(f"click_exact_button: clicked candidate index {chosen['index']} for selector '{selector}'")
        return True
    except Exception as e:
        logger.error(f"click_exact_button: failed to click chosen candidate for '{selector}': {e}")
        return False

async def _safe_click(page: Page, selectors: List[str], timeout: int = 700, post_click_wait: int = 400) -> bool:
    """
    Click helper:
        - Tries selectors in order
        - Short timeout per selector (700ms)
        - Ensures element is visible AND enabled
        - Prevents clicking an invisible or zero-size element
        - Logs clearly what happened

    Params:
        page: the page to investigate
        selectors: the list of potential selectors

    Returns:
        True if a click.  False otherwise.
    """

    # 1. Pre-filtering of Playwright invalid selectors
    cleaned_selectors = []
    for s in selectors:
        try:
            # Playwright triggers an Exception if invalid selector
            page.locator(s)
            cleaned_selectors.append(s)
        except Exception:
            logger.debug(f"Sélecteur ignoré (non valide Playwright) : {s}")

    if not cleaned_selectors:
        logger.warning("Aucun sélecteur valide fourni à safe_click()")
        return False

    # 2. Running through valid selectors
    for selector in cleaned_selectors:
        try:
            logger.debug(f"Tentative : {selector}")

            # a) waiting for it is present and visible (short timeout)
            # await page.wait_for_selector(selector, state="visible", timeout=timeout)

            locator = page.locator(selector)

            # b) checking actual visibility (not just ste='visible')
            if not await locator.is_visible():
                logger.debug(f"Non visible malgré wait_for_selector : {selector}")
                continue

            # c) checking clickability (avoiding overlay/disabled)
            if not await locator.is_enabled():
                logger.debug(f"Le sélecteur est désactivé : {selector}")
                continue

            # d) click
            clicked_ok = await _click_exact_button(page, selector, timeout=timeout)
            if not clicked_ok:
                logger.debug(f"click_exact_button failed for {selector}")
                continue

            logger.info(f"Clic effectué via click_exact_button : {selector}")

            # e) waiting a little bit for allowing DOM update
            await asyncio.sleep(post_click_wait)

            return True

        except PlaywrightTimeoutError:
            logger.debug(f"Timeout sur : {selector}")
            continue
        except Exception as e:
            logger.error(f"Erreur click {selector} : {e}")
            continue

    logger.warning("Aucun clic réussi sur la liste fournie.")
    return False

async def _handle_multistep_login(page: Page, step_selectors: List[List[str]], wait_after_click: int = 2000, max_steps: int = None) -> int:
    """
    Handles multistep login by clicking sequentially through selectors at each step.

    Improvements:
        - Stops early if no selector clickable
        - Verifies DOM changes or URL change to detect real step progression
        - Optional max_steps limit
        - Logs each action clearly

    Params:
        page: the page to investigate
        step_selectors: list of lists of potential selectors per step
        wait_after_click: ms to wait after a successful click
        max_steps: optional maximum number of steps to attempt

    Returns:
        Number of steps successfully completed
    """
    logger.info(f"Starting multi-step login with {len(step_selectors)} steps")

    steps_completed = 0

    for step_num, selectors in enumerate(step_selectors, start=1):
        if max_steps and steps_completed >= max_steps:
            logger.info(f"Max steps {max_steps} reached, stopping")
            break

        logger.debug(f"Step {step_num}: trying selectors {selectors}")

        # snapshot current URL and DOM content for comparison
        try:
            url_before = page.url
            dom_before = await page.content()
        except Exception:
            url_before, dom_before = None, None

        clicked = await _safe_click(page, selectors)
        if not clicked:
            logger.warning(f"Step {step_num} failed: no clickable selector, stopping")
            break

        # wait for DOM / page update
        await asyncio.sleep(wait_after_click / 1000)

        # detect if something changed (URL or DOM)
        url_after = page.url
        dom_after = await page.content()

        url_changed = url_before != url_after if url_before and url_after else False
        dom_changed = dom_before != dom_after if dom_before and dom_after else False

        if url_changed or dom_changed:
            steps_completed += 1
            logger.debug(f"Step {step_num} completed (change detected)")
        else:
            logger.warning(f"Step {step_num} click did not trigger visible change, stopping")
            break

    logger.info(f"Multi-step login finished: {steps_completed} step(s) completed")
    return steps_completed
