"""
Validation module for closed Shadow DOM detection.

This module validates whether sites filtered as "closed Shadow DOM" actually use
closed Shadow DOM for their authentication forms.

Usage:
    from ClosedShadowDOMValidator import validate_closed_shadow_dom, validate_batch

    # Single site
    result = await validate_closed_shadow_dom('https://nvidia.com')

    # Batch
    df_results = await validate_batch(['https://nvidia.com', 'https://coinbase.com'])
"""

from import_data import *

__all__ = ["validate_closed_shadow_dom", "validate_batch"]

async def _find_all_shadow_roots(page) -> List[Dict]:
    """Finds all Shadow DOM roots, including suspected closed ones."""

    result = await safe_evaluate(
        page,
        """
        () => {
            function findShadowRoots(element, depth = 0) {
                const roots = [];

                // Check for open Shadow DOM
                if (element.shadowRoot) {
                    const hasPassword = element.shadowRoot.querySelector('input[type="password"]') !== null;
                    const text = element.shadowRoot.textContent?.toLowerCase() || '';
                    const hasWebAuthn = /passkey|webauthn|fido|security.?key/i.test(text);

                    roots.push({
                        tag: element.tagName,
                        mode: 'open',
                        has_password: hasPassword,
                        has_webauthn: hasWebAuthn,
                        depth: depth
                    });

                    // Recurse into shadow DOM
                    for (const child of element.shadowRoot.children) {
                        roots.push(...findShadowRoots(child, depth + 1));
                    }
                }

                // Check for suspected closed Shadow DOM
                const isWebComponent = element.tagName.includes('-');
                const hasHeight = element.scrollHeight > 0;
                const hasChildren = element.childNodes.length > 0;
                const noQueryable = element.querySelectorAll('*').length === 0;

                if (isWebComponent || (hasChildren && hasHeight && noQueryable)) {
                    roots.push({
                        tag: element.tagName,
                        mode: 'closed',  // suspected
                        has_password: false,  // can't check
                        has_webauthn: false,  // can't check
                        depth: depth,
                        is_web_component: isWebComponent
                    });
                }

                // Recurse into regular DOM
                for (const child of element.children) {
                    roots.push(...findShadowRoots(child, depth));
                }

                return roots;
            }

            return findShadowRoots(document.body);
        }
        """,
        default=[]
    )

    return result

async def validate_closed_shadow_dom(
    site_url: str,
    headless: bool = True,
    take_screenshot: bool = True,
    timeout: int = 30000
) -> Dict:
    """
    Validates whether a site uses closed Shadow DOM for authentication.

    Args:
        site_url: URL to validate
        headless: Run in headless mode
        take_screenshot: Save screenshot for manual review
        timeout: Timeout in milliseconds

    Returns:
        {
            'site_url': str,
            'is_closed_shadow_dom': bool,
            'confidence': str,  # 'high' | 'medium' | 'low' | 'unknown'
            'has_open_shadow': bool,
            'has_closed_shadow': bool,
            'password_accessible': bool,
            'shadow_count': int,
            'screenshot': Optional[str],
            'conclusion': str,
            'error': Optional[str]
        }
    """
    result = {
        'site_url': site_url,
        'is_closed_shadow_dom': False,
        'confidence': 'unknown',
        'has_open_shadow': False,
        'has_closed_shadow': False,
        'password_accessible': False,
        'shadow_count': 0,
        'screenshot': None,
        'conclusion': '',
        'error': None
    }

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=headless)
            page = await browser.new_page()

            # Navigate
            try:
                await page.goto(site_url, timeout=timeout, wait_until='domcontentloaded')
            except PlaywrightTimeout:
                result['error'] = 'Navigation timeout'
                await browser.close()
                return result

            await asyncio.sleep(2)
            sign_in_selectors = [
                'text=/sign.?in/i', 'text=/log.?in/i',
                'a:has-text("Sign in")', 'button:has-text("Sign in")',
                'a[href*="login"]', 'a[href*="signin"]'
            ]

            # Click Sign In
            for selector in LOGIN_KEYWORDS: #sign_in_selectors:
                try:
                    await page.locator(selector).first.click(timeout=2000)
                    logger.info(f"[{site_url}] Clicked: {selector}")
                    break
                except:
                    continue

            await asyncio.sleep(3)

            # Find shadow roots
            shadows = await _find_all_shadow_roots(page)
            result['shadow_count'] = len(shadows)

            open_shadows = [s for s in shadows if s['mode'] == 'open']
            closed_shadows = [s for s in shadows if s['mode'] == 'closed']

            result['has_open_shadow'] = len(open_shadows) > 0
            result['has_closed_shadow'] = len(closed_shadows) > 0

            # Check password accessibility
            password_count = await page.locator('input[type="password"]').count()
            result['password_accessible'] = password_count > 0

            # Take screenshot
            if take_screenshot:
                try:
                    os.makedirs('validation_screenshots', exist_ok=True)
                    filename = site_url.replace('https://', '').replace('http://', '').replace('/', '_')[:50]
                    path = f"validation_screenshots/{filename}.png"
                    await page.screenshot(path=path)
                    result['screenshot'] = path
                except Exception as e:
                    logger.warning(f"Screenshot failed: {e}")

            # Determine verdict
            if result['has_closed_shadow'] and not result['password_accessible']:
                result['is_closed_shadow_dom'] = True
                result['confidence'] = 'high'
                result['conclusion'] = f"HIGH confidence: {len(closed_shadows)} closed shadow root(s), no accessible password"

            elif result['has_open_shadow'] and not result['password_accessible']:
                open_with_pwd = [s for s in open_shadows if s['has_password']]
                if open_with_pwd:
                    result['is_closed_shadow_dom'] = False  # Open, not closed
                    result['confidence'] = 'medium'
                    result['conclusion'] = f"OPEN Shadow DOM (not closed): {len(open_with_pwd)} open shadow(s) with password"
                else:
                    result['confidence'] = 'low'
                    result['conclusion'] = f"LOW confidence: {len(open_shadows)} shadow(s) but no password found"

            elif result['password_accessible']:
                result['is_closed_shadow_dom'] = False
                result['confidence'] = 'low'
                result['conclusion'] = "FALSE POSITIVE: Password accessible in regular DOM"

            else:
                result['confidence'] = 'unknown'
                result['conclusion'] = "UNKNOWN: No shadow DOM, no password input found"

            await browser.close()
            logger.info(f"[{site_url}] {result['conclusion']}")

    except Exception as e:
        logger.error(f"[{site_url}] Error: {e}")
        result['error'] = str(e)

    return result


async def validate_batch(
    site_urls: List[str],
    headless: bool = True,
    take_screenshots: bool = False,
    max_concurrent: int = 3
) -> tuple[pd.DataFrame, dict]:
    """
    Validates multiple sites concurrently.

    Params:
        site_urls: List of URLs to validate
        headless: Run in headless mode
        take_screenshots: Save screenshots
        max_concurrent: Max concurrent validations

    Returns:
        DataFrame with validation results
        Dict with raw statistics
    """
    semaphore = asyncio.Semaphore(max_concurrent)

    async def validate_with_limit(url, bar):
        async with semaphore:
            result = await validate_closed_shadow_dom(url, headless, take_screenshots)
            bar()  # <-- tick quand la tâche est terminée
            return result

    logger.info(f"Validating {len(site_urls)} sites (max {max_concurrent} concurrent)...")
    with alive_bar(
        len(site_urls),
        title="Validating closed shadow DOM",
    ) as bar:
        results = await asyncio.gather(
            *[validate_with_limit(url, bar) for url in site_urls]
        )

    df = pd.DataFrame(results)

    # --- Raw statistics only ---
    stats = {
        "total_sites": len(df),
        "closed_shadow_confirmed": (df["is_closed_shadow_dom"] == True).sum(),
        "confidence_high": (df["confidence"] == "high").sum(),
        "confidence_medium": (df["confidence"] == "medium").sum(),
        "confidence_low": (df["confidence"] == "low").sum(),
    }

    _save_results(df)

    return df, stats

def _save_results(df: pd.DataFrame, filepath: str = GROUNDTRUTH_PLOT+'groundtruth_filtering_closedshadow_validation.csv'):
    """
    Save validation results to CSV.
    """
    df.to_csv(filepath, index=False)
    logger.info(f"Results saved to: {filepath}")
