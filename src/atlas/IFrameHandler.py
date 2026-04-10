"""
Fetches all accessible iframes (HTML element for inserting another web page
inside an existing one) and applies the same detectors/heuristics as for DOM.

Collects results iframe per iframe in a dictionary.  The iframe URL is the key.
"""

from import_data import *

__all__ = ["apply_dom_detectors_to_frames"]

async def apply_dom_detectors_to_frames(page: Page, dom_detectors: List):
    """
    Applies a list of async functions from DOM detection (e.g.,  detect_password_input,
    detect_credentials_api,) to each iframe of a given page.

    Each function is supposed to accept an iframe or a page as argument and to return a result

    Params:
        page: the page to investigate
        dom_detectors: the list of functions for DOM detection

    Returns:
        dictionary with iframe.url as key and lists dectection results as value.
    """
    safe_frames = []
    frames = page.frames
    for f in frames:
        try:
            url = f.url
        except:
            continue

        if any(p in url for p in CF_IGNORE_PATTERNS):
            logger.debug(f"Ignoring Cloudflare frame: {url}")
            continue

        safe_frames.append(f)

    results = {}

    logger.info(f"Application de {len(dom_detectors)} détecteurs DOM sur {len(safe_frames)} frames")

    for frame in safe_frames:
        frame_results = []
        for detector in dom_detectors:
            try:
                res = await detector(frame)
                frame_results.append(res)
                logger.debug(f"Détecteur {detector.__name__} sur frame {frame.url} => {res}")
            except Exception as e:
                error_msg = f"error: {str(e)}"
                frame_results.append(error_msg)
                logger.error(f"Erreur dans détecteur {detector.__name__} frame {frame.url}: {e}")
        results[frame.url] = frame_results

    return results

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

async def _get_all_frames(page: Page) -> List[Frame]:
    """
    Recursively fetches all accessible iframes of a given page.

    Params:
        page: the page to investigate

    Returns:
            list of accessible iframes
    """
    frames = []

    def collect_frames(frame):
        frames.append(frame)
        for child in frame.child_frames:
            collect_frames(child)

    try:
        collect_frames(page.main_frame)
        logger.debug(f"Nombre total de frames récupérées: {len(frames)}")
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des frames: {e}")

    return frames
