"""
The local storage is a technique for storing data in a web browser.  It allows
for persistent storage, like cookies, with a larger capacity and whithout
requiring to add data in HTTP request headers.

It comes in 2 flavors: local storage (equivalent to persistent cookies) and
session storage (equivalent to session cookies).

This analyses cookies, local storage and session storage by looking for tokens,
login state or WebAuth hints.
"""

from import_data import *
from utils import *

__all__ = ["analyze_storage_and_cookies"]

async def analyze_storage_and_cookies(page: Page, context: BrowserContext) -> Dict[str, Any]:
    """
    Analyzes cookies, local storage, and session straoge of a given page in a given context.

    Params:
        page: the page to investigate
        contect: the browser context

    Returns:
        dictionary made of booleans (see contains_keywords) and raw data (i.e., cookies
        and storages)
    """
    logger.info("Début de l'analyse des cookies, localStorage et sessionStorage")
    cookies = await _get_cookies(context)
    local_storage = await _safe_get_storage(page, storage_type="local")
    session_storage = await _safe_get_storage(page, storage_type="session")

    # Convert cookies list en dict {name: value} pour analyse des keywords
    cookies_dict = {cookie['name']: cookie['value'] for cookie in cookies}

    results = {
        "cookies_contain_fido": _contains_keywords(cookies_dict),
        "local_storage_contains_fido": _contains_keywords(local_storage),
        "session_storage_contains_fido": _contains_keywords(session_storage),
        "raw_cookies": cookies,
        "raw_local_storage": local_storage,
        "raw_session_storage": session_storage
    }
    logger.info("Fin de l'analyse du stockage et cookies")
    return results

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

async def _get_cookies(context: BrowserContext) -> List[Dict[str, Any]]:
    """
    Fetches all cookies of a given browser context.

    Params:
        context: browser context

    Returns:
        list of dictionaries
    """
    try:
        cookies = await context.cookies()
        logger.debug(f"Nombre de cookies récupérés : {len(cookies)}")
        return cookies
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des cookies: {e}")
        return []

async def _safe_get_storage(page: Page, storage_type: Literal["local", "session"] = "local") -> Dict[str, str]:
    """
    Safely fetches all items from localStorage or sessionStorage of a page.

    Params:
        page: the Playwright Page object to investigate
        storage_type: "local" for localStorage, "session" for sessionStorage

    Returns:
        dictionary where keys are storage keys and values are stored strings
    """
    if storage_type not in {"local", "session"}:
        raise ValueError(f"Unknown storage_type: {storage_type}")

    js_code = f"""
    () => {{
        try {{
            const items = {{}};
            const storage = window.{storage_type}Storage;
            if (!storage) return items;
            for (let i = 0; i < storage.length; i++) {{
                const key = storage.key(i);
                items[key] = storage.getItem(key);
            }}
            return items;
        }} catch (e) {{
            return {{}};
        }}
    }}
    """

    storage_data = await safe_evaluate(page, js_code,default={})

    if not isinstance(storage_data, dict):
        storage_data = {}

    logger.debug(f"{storage_type}Storage récupéré avec {len(storage_data)} items")
    return storage_data

def _contains_keywords(storage_dict: Dict[str, Optional[str]], keywords: List[str] = None) -> bool:
    """
    Applies DOM heuristics (i.e., keywords search) on a given storage.  The heuristics are
    applied on key or values of the storage.

    Params:
        storage_dict: dictionary representing the storage
        keywords: list of keywords to search for (optional)

    Returns:
        True if a keyword is found.  False otherwise
    """
    if keywords is None:
        keywords = FIDO_KEYWORDS
    for key, value in storage_dict.items():
        key_lower = key.lower() if key else ""
        value_lower = value.lower() if value else ""
        for kw in keywords:
            if kw in key_lower or kw in value_lower:
                logger.debug(f"Mot-clé '{kw}' trouvé dans storage (clé: {key}, valeur: {value})")
                return True
    return False
