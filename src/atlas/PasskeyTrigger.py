"""
Tries to validate full FIDO2 classification by actively triggering
a WebAuthn flow ("Sign in with passkey", "Use security key", etc.).  Possibly,
it may also retrieve COSE parameters associated to creation/get credentials if
exposed.

This is also used for capturing FIDO2 challenge.
"""

from import_data import *
from utils import *

__all__ = ["validate_fido_classification"]

async def validate_fido_classification(page: Page, timeout_ms: int = TIMEOUT_VALIDATION) -> Dict[str, Any]:
    """
    Full pipeline for validating FIDO classification. It looks for:
        - a passkey button
        - click on it
        - wait for any call to WebAuthn
        - possibly extracts COSE algorithms

    Params:
        page, the page that potentially encompasses the FIDO authentication

    Returns:
        dictionary as follows:
            {
                "passkey_button_clicked": bool,
                "clicked_selector": Optional[str],
                "webauthn_called": bool,
                "create_calls": [...],
                "get_calls": [...],
                "cose_algorithms": [...],
            }
    """
    logger.info("[PasskeyTrigger] départ")

    result = {
        "passkey_button_clicked": False,
        "clicked_selector": None,
        "webauthn_called": False,
        "create_calls": [],
        "get_calls": [],
        "cose_algorithms": [],
        "error": None,
    }

    sel = await _try_trigger_passkey_login(page)

    if sel == "No Data -- Waiting for input from users to trigger WebAuthn":
        result["error"] = sel
        return result

    if not sel:
        return result

    result["passkey_button_clicked"] = True
    result["clicked_selector"] = sel

    # 2 → attendre un éventuel appel WebAuthn via le hook
    await asyncio.sleep(timeout_ms / 1000)

    _, params = await detect_credentials_api(page)
    create_calls = params.get("create", []) or []
    get_calls = params.get("get", []) or []

    result["create_calls"] = create_calls
    result["get_calls"] = get_calls

    iframe_results = await apply_dom_detectors_to_frames(
        page,
        [detect_credentials_api]
    )

    # Merge iframe calls into main get/create lists
    for frame_url, frame_outputs in iframe_results.items():
        for entry in frame_outputs:
            if isinstance(entry, dict):
                # Merge create()
                if isinstance(entry.get("create"), list):
                    create_calls.extend(entry["create"])
                # Merge get()
                if isinstance(entry.get("get"), list):
                    get_calls.extend(entry["get"])

    if not create_calls and not get_calls:
        return result

    def _is_real_webauthn_call(entry):
        obj = safe_json_load(entry) if isinstance(entry, str) else entry
        if not isinstance(obj, dict):
            return False
        # Un vrai appel WebAuthn a forcément une clé "publicKey"
        args = obj.get("args", [])
        if isinstance(args, list) and len(args) > 0:
            return "publicKey" in (args[0] if isinstance(args[0], dict) else {})
        # Fallback : si la structure est déjà dépliée
        return "publicKey" in obj or "challenge" in obj

    real_get_calls = [e for e in get_calls if _is_real_webauthn_call(e)]
    real_create_calls = [e for e in create_calls if _is_real_webauthn_call(e)]

    if not real_get_calls and not real_create_calls:
        return result

    result["webauthn_called"] = True

    # 3 → extraire les algorithmes COSE
    filtered_create = []
    for entry in create_calls:
        obj = safe_json_load(entry) if isinstance(entry, str) else entry
        if obj:
            filtered_create.append(obj)

    cose = _extract_cose_algorithms(real_create_calls)#(filtered_create)
    result["cose_algorithms"] = cose

    logger.info(f"[PasskeyTrigger] COSE algorithms extraits : {cose}")

    return result

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _extract_cose_algorithms(create_calls: List[Union[str, dict]]) -> List[int]:
    """
    Tries to extract COSE algorithms for create credentials

    Params:
        create_calls, data structure containing create credentials
        (see https://webauthn.guide/)

    Returns:
        a list of COSE algorithms if any (possibly empty)
    """
    algs = set()

    for raw in create_calls or []:
        obj = safe_json_load(raw) if isinstance(raw, str) else raw
        if not isinstance(obj, dict):
            continue

        # 1. recursively search for publicKey
        public_keys = []

        def walk(node):
            if isinstance(node, dict):
                if "publicKey" in node:
                    public_keys.append(node["publicKey"])
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(obj)

        if not public_keys:
            continue

        for pk in public_keys:

            # 2. recursive search of pubKeyCredParams if publicKey found
            params = []

            def collect_params(n):
                if isinstance(n, dict) and "pubKeyCredParams" in n:
                    if isinstance(n["pubKeyCredParams"], list):
                        params.extend(n["pubKeyCredParams"])
                if isinstance(n, dict):
                    for v in n.values():
                        collect_params(v)
                elif isinstance(n, list):
                    for v in n:
                        collect_params(v)

            collect_params(pk)

            # 3. if no explicit params, assume ES256 (-7)
            if not params:
                algs.add(-7)
                continue

            # 4. extract alg integers
            for p in params:
                if not isinstance(p, dict):
                    continue
                alg = p.get("alg")
                if isinstance(alg, str):
                    try:
                        alg = int(alg)
                    except:
                        continue
                if isinstance(alg, int):
                    algs.add(alg)

    return sorted(algs)

async def _try_trigger_passkey_login(page: Page) -> Optional[str]:
    """
    Searches for a button triggering WebAuthn/passkey flow. If found, click on it.

    Returns:
        selector/text if a click occurred
        "No Data -- Waiting for input from users to trigger WebAuthn" if user input is required
        None otherwise
    """

    passkey_patterns = re.compile(
        r"log\s*in.*passkey|sign\s*in.*passkey|continue.*passkey|log\s*in.*security device",
        re.I
    )

    _KEYWORDS_LOWER = [kw.lower() for kw in UI_KEYWORDS]

    async def matches_passkey_keyword(text: str) -> bool:
        t = text.lower().strip()
        return any(kw in t for kw in _KEYWORDS_LOWER)

    async def _detect_waiting_user_input() -> bool:
        """
        Detect if the page is waiting for user input before WebAuthn can start.
        """
        try:
            input_field = await page.query_selector(
                "input[type='text'], input[type='email'], input[type='password'], "
                "input[name*='user' i], input[name*='email' i], input[placeholder*='user' i]"
            )

            if input_field and await input_field.is_visible():
                return True
        except Exception:
            pass

        return False

    # broaden element search while staying backward compatible
    try:
        buttons = await page.query_selector_all("button, [role='button'], a")
    except:
        buttons = await page.query_selector_all("button")

    # --- FIRST PASS: regex on visible text ---
    for button in buttons:
        try:
            # Texte visible
            text = (
                (await button.inner_text())
                or (await button.text_content())
                or ""
            ).strip().lower()

            # Si texte vide ou trop court, enrichir avec les attributs
            if len(text) < 3:
                for attr in ["aria-label", "title", "data-testid",
                             "data-action", "data-method", "name", "id"]:
                    try:
                        val = await button.get_attribute(attr)
                        if val:
                            text = (text + " " + val.lower()).strip()
                    except:
                        pass
        except:
            text = ""

        #if passkey_patterns.search(text):
        if await matches_passkey_keyword(text):
            try:
                await button.click(timeout=TIMEOUT_CLICK)

            except Exception:
                try:
                    await button.evaluate("""
                        el => {
                            try {
                                el.disabled = false;
                                el.removeAttribute("disabled");
                                el.style.pointerEvents = "auto";
                                el.click();
                            } catch(e){}
                        }
                    """)
                except Exception:
                    pass

            if hasattr(page, "_atlas_results"):
                page._atlas_results["nb_clicks"] = page._atlas_results.get("nb_clicks", 0) + 1

            await asyncio.sleep(0.5)
            await page.wait_for_timeout(TIMEOUT_TRIGGER)

            return text

    for sel in PASSKEY_BUTTON_SELECTORS:
        try:
            try:
                btn = await page.query_selector(sel)
            except Exception:
                continue

            if btn:

                try:
                    await btn.wait_for_element_state("visible", timeout=TIMEOUT_VISIBLE)
                except:
                    pass

                try:
                    await page.wait_for_function(
                        "el => !el.disabled && el.getAttribute('aria-disabled') !== 'true'",
                        btn,
                        timeout=TIMEOUT_ENABLE
                    )
                except:
                    pass

                try:
                    await btn.click(timeout=TIMEOUT_CLICK)

                except Exception:
                    try:
                        await btn.evaluate("""
                            el => {
                                try {
                                    el.disabled = false;
                                    el.removeAttribute("disabled");
                                    el.style.pointerEvents = "auto";
                                    el.click();
                                } catch(e){}
                            }
                        """)
                    except Exception:
                        pass

                if hasattr(page, "_atlas_results"):
                    page._atlas_results["nb_clicks"] = page._atlas_results.get("nb_clicks", 0) + 1

                await asyncio.sleep(0.5)
                await page.wait_for_timeout(TIMEOUT_TRIGGER)

                return sel

        except Exception:
            pass

    # --- FINAL CHECK: user input required before passkey flow ---
    if await _detect_waiting_user_input():
        return "No Data -- Waiting for input from users to trigger WebAuthn"

    return None
