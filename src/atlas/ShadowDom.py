"""
Shadow DOM is a web technology for creating encapsulated components, with their
own DOM hidden and distinct from the main DOM.

This allows for detecting shadow roots (i.e., the shadow DOM starting point, in
some way identical to <html> element in the main DOM), as well as a recursive
exploration of shadow trees (i.e., the internal DOM of the shadow DOM, with its
own elements and styles) to search for elements.
"""

from import_data import *

__all__ = ["detect_password_inputs_in_shadow_dom", "detect_password_input", "detect_webauthn_keywords_in_shadow_dom"]

async def detect_password_inputs_in_shadow_dom(frame: Frame) -> bool:
    """
    Detects visible password inputs in shadow roots of a given frame.
    Uses safe_await for robustness and short timeouts to avoid blocking.

    Parameters:
        frame: Playwright Frame to investigate.

    Returns:
        True if a visible password input is detected, False otherwise.
    """
    # Collect all potential password inputs in shadow DOM
    password_inputs = await _query_selector_in_shadow_roots(frame, "input[type='password']")
    if not password_inputs:
        logger.info("Aucun input[type='password'] trouvé dans le shadow DOM")
        return False

    visible_inputs = []

    # Check visibility for each input safely
    for el in password_inputs:
        try:
            visible = await safe_await(
                lambda: el.evaluate("""
                    (e) => {
                        // Check basic visibility
                        if (e.offsetParent === null) return false;
                        // width/height or client rects for hidden/styled inputs
                        return (e.offsetWidth > 0 && e.offsetHeight > 0) || e.getClientRects().length > 0;
                    }
                """),
                timeout=0.3,  # max 300ms par élément
                default=False,
                label="check_password_input_visibility"
            )
            if visible:
                visible_inputs.append(el)
        except Exception as e:
            logger.debug(f"Erreur safe_await visibilité input password: {e}")

    detected = len(visible_inputs) > 0
    logger.info(f"Visible password inputs in shadow DOM: {detected} ({len(visible_inputs)}/{len(password_inputs)})")
    return detected

async def detect_password_input(page: Page, timeout: int=2000) -> bool:
    """
    Detects presence of input[type='password'] in the main DOM (outside shadow roots).

    Returns True if a password input is present, False otherwise.
    """
    try:
        result = await page.evaluate("""() => {
            return !!document.querySelector("input[type='password']");
        }""")
        logger.debug("detect_password_input: %s", result)
        return result
    except Exception as e:
        logger.error("Erreur detect_password_input: %s", e)
        return False

async def detect_webauthn_keywords_in_shadow_dom(
    frame: Frame,
    keywords: List[str],
) -> bool:
    """
    Looks for WebAuthn-related keywords in all shadow roots of a given frame.
    Uses safe_await with short timeouts to avoid blocking on large shadow trees.

    Parameters:
        frame: Playwright Frame to investigate
        keywords: list of WebAuthn-related keywords

    Returns:
        True if a keyword is found in shadow DOM, False otherwise.
    """
    shadow_roots = await _get_all_shadow_roots(frame)

    if not shadow_roots:
        logger.info("Aucun shadow root détecté pour analyse WebAuthn")
        return False

    keywords_lower = [kw.lower() for kw in keywords]

    for idx, shadow_root in enumerate(shadow_roots):
        try:
            text_content = await safe_await(
                lambda: shadow_root.evaluate(
                    "root => root.innerText || root.textContent || ''"
                ),
                timeout=0.4,   # max 400ms par shadow root
                default="",
                label="shadow_dom_webauthn_text_extract"
            )

            if not text_content:
                continue

            text_lower = text_content.lower()

            for keyword in keywords_lower:
                if keyword in text_lower:
                    logger.info(
                        f"Mot-clé WebAuthn '{keyword}' détecté "
                        f"dans shadow DOM (root {idx+1}/{len(shadow_roots)})"
                    )
                    return True

        except Exception as e:
            logger.debug(
                f"Erreur analyse WebAuthn shadow root {idx+1}: {e}"
            )

    logger.info("Aucun mot-clé WebAuthn détecté dans le shadow DOM")
    return False

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

async def _get_all_shadow_roots(frame: Frame) -> List[ElementHandle]:
    """
    Fetches all shadow roots accessible from a given frame and recursively explores children
    in those shadow toots.

    Params:
        frame: the frame to investigate.

    Returns:
        list of roots elements of shadow ROM.
    """
    shadow_roots = []

    async def recurse(element: ElementHandle):
        try:
            shadow_root = await element.evaluate_handle("el => el.shadowRoot || null")
            if not shadow_root:
                return

            # Tests if shadowRoot can be exploited (trying to avoid errors)
            is_shadow = await shadow_root.evaluate("root => root !== null && typeof root.children !== 'undefined'")
            if not is_shadow:
                return

            shadow_roots.append(shadow_root)

            # Fetching children of shadowRoot
            children = await shadow_root.evaluate_handle("root => Array.from(root.children)")
            children_elements = await children.get_properties()
            for child in children_elements.values():
                child_element = child.as_element()
                if child_element:
                    await recurse(child_element)

        except Exception as e:
            logger.debug(f"Erreur lors de la récupération du shadow root: {e}")

    try:
        elements = await frame.query_selector_all("*")
    except Exception:
        pass
    logger.info(f"Nombre d'éléments dans le frame pour exploration shadow roots : {len(elements)}")
    for el in elements:
        await recurse(el)

    logger.info(f"Total shadow roots trouvés : {len(shadow_roots)}")
    return shadow_roots

async def _query_selector_in_shadow_roots(frame: Frame, selector: str) -> List[ElementHandle]:
    """
    Looks, in all shadow roots of a given frame, for elements corresponding to a given selector

    Params:
        frame: the frame to investigate
        selector: the given selector

    Returns:
        A list of found elements.
    """
    matching_elements = []
    shadow_roots = await _get_all_shadow_roots(frame)

    for shadow_root in shadow_roots:
        try:
            # Try direct selector on shadow root
            el = await shadow_root.query_selector(selector)
            if el:
                matching_elements.append(el)
            else:
                # Fallback : query inside shadow host (works for older browsers / polyfills)
                host = shadow_root.host
                if host:
                    el2 = el2 = host.locator(f":scope >>> {selector}")
                    count = await el2.count()
                    if count > 0:
                        matching_elements.append(el2)

        except Exception as e:
            logger.debug(f"Erreur lors de la recherche du sélecteur '{selector}' dans un shadow root : {e}")


    logger.info(f"Éléments trouvés avec le sélecteur '{selector}' dans shadow DOM : {len(matching_elements)}")
    return matching_elements
