"""
Wrappers for useful functions
"""

from import_data import *
from urllib.parse import urlparse

async def safe_evaluate(page: Page, js_fn: str, default=None):
    """
    Execute a JS function in the page context safely.

    Handles:
      - document.body being null
      - exceptions in page.evaluate
      - returns a default value if anything goes wrong

    Params:
        page: Playwright Page object
        js_fn: JavaScript code to execute as a string function "() => { ... }"
        default: value to return if execution fails

    Returns:
        Result of JS evaluation, or default if failed.
    """
    try:
        result = await page.evaluate(js_fn)
        if result is None:
            return default
        return result
    except Exception as e:
        logger.warning(f"[safe_evaluate] Exception during JS evaluation: {e}")
        return default

async def safe_await(factory, timeout: float, default=None, label=""):
    """
    Safely executes an asynchronous operation with a strict timeout and
    guaranteed cleanup, preventing pipeline stalls caused by long-running
    or hanging coroutines.

    The function expects a *callable* (factory) returning a coroutine,
    not a coroutine object itself. This design ensures that coroutine
    creation is fully controlled and that execution can be safely cancelled
    if a timeout occurs.

    Parameters:
        factory : Callable[[], Coroutine]
            A zero-argument callable returning the coroutine to execute.
            Passing a coroutine object directly is considered a programming
            error and will raise a RuntimeError.

        timeout : float
            Maximum execution time in seconds. If the timeout is exceeded,
            the underlying task is cancelled and the function returns `default`.

        default : Any, optional
            Value returned when a timeout or an exception occurs.
            Defaults to None.

        label : str, optional
            Human-readable identifier used for logging and diagnostics.
            This label appears in timeout and error logs to facilitate
            debugging and performance analysis.

    Returns:
        The result of the awaited coroutine if it completes successfully
        within the specified timeout; otherwise, the provided `default`
        value.
    """
    try:
        return await asyncio.wait_for(factory(), timeout=timeout)
    except PlaywrightTimeoutError:
        return default
    except asyncio.TimeoutError:
        return default
    except Exception:
        return default

async def get_etld1(url: str) -> str:
    parsed = urlparse(url)
    parts = parsed.hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else parsed.hostname

async def save_screenshot(page: Page, url: str):
    """
    Saves the login page screenshot into a zip file.

    Params:
        page, the login page
        url, url of the login page (for building filename)
    """
    filename = sanitize_filename(extract_domain(url))+".png"
    filepath = os.path.join(SCREENSHOT_DIR, filename)
    await page.screenshot(path=filepath)

    with zipfile.ZipFile(SCREENSHOTS_ZIP, 'a', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(filepath, arcname=filename)

    logger.info(f"Screenshot of {url} in {filepath}")
    os.remove(filepath)

def safe_json_load(x: Union[str, dict]) -> Any:
    """
    Returns parsed object if x is JSON string, otherwise return x (if dict).
    """
    if isinstance(x, dict):
        return x
    if not isinstance(x, str):
        return None
    try:
        return json.loads(x)
    except Exception:
        return None

def get_extension_from_url(url: str) -> str:
    """
    Extracts the final domain from a given URL.  Example https://www.lesoir.be -> .be

    Params:
        url: the URL to parse

    Returns:
        a string representing the final domain
    """
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    if hostname:
        # Takes the last element of the domain name
        domain_parts = hostname.split('.')
        if len(domain_parts) >= 0:
            return '.' + domain_parts[-1]
    return None

def sanitize_filename(url: str) -> str:
    """
    Converts an URL into a secure filename, replacing non valid characters.
    Useful for screenshots

    Example : https://example.com/login → example_com_login
    """
    import re
    sanitized = re.sub(r'[^a-zA-Z0-9_-]', '_', url)
    return sanitized.strip('_')

def extract_domain(url: str) -> str:
    """
    Exacts domain from a full URL

    Example :
        - https://sub.example.com/login → sub.example.com
        - https://www.sub.example.com → sub.example.com
    """
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # Remove 'www.' prefix if present
    if domain.startswith("www."):
        domain = domain[4:]

    return domain

def extract_label(url: str) -> str:
    """
    Extracts the label from a given URL.  Example https://www.lesoir.be -> lesoir

    Params:
        url: the URL to parse

    Returns:
        a string representing the label
    """
    parsed_url = urlparse(url)
    label = parsed_url.netloc

    # Remove 'www.' prefix if present
    if label.startswith("www."):
        label = label[4:]
    # can have urls starting with www.www.
    if label.startswith("www."):
        label = label[4:]
    # removing extension
    label_parts = label.split('.')
    return label_parts[0]

def ensure_directory_exists(path: str) -> None:
    """
    Creates a directory if it does not exist yet.

    Useful for all outputs.
    """
    import os
    if not os.path.exists(path):
        os.makedirs(path)

def is_valid_url(url: str) -> bool:
    """
    Checks very basically whethe a URL is valid
    """
    from urllib.parse import urlparse
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def truncate_string(s: str, max_length: int = 100) -> str:
    """
    Truncates a string that is too long with ...
    """
    if len(s) > max_length:
        return s[:max_length - 3] + "..."
    return s

def flatten_list(nested_list):
    """
    Flattens a nested list (whatever the list depth).
    """
    flat_list = []
    for item in nested_list:
        if isinstance(item, (list, tuple)):
            flat_list.extend(flatten_list(item))
        else:
            flat_list.append(item)
    return flat_list

def zip_old_logs_file():
    """
    Zipping old logs file into another folder so that they are not to big
    """
    log_dir = "../CSV/Scraping/logs_parallel"
    zip_filename = os.path.join("../CSV/Scraping/zip_logs", f"logs_{datetime.now().strftime('%Y-%m-%d')}.zip")

    files_to_zip = [f for f in os.listdir(log_dir) if os.path.isfile(os.path.join(log_dir, f))]

    try:
        if files_to_zip:
            with zipfile.ZipFile(zip_filename, 'w', compression=zipfile.ZIP_DEFLATED) as zipf:
                for file in files_to_zip:
                    file_path = os.path.join(log_dir, file)
                    zipf.write(file_path, arcname=file)
                    os.remove(file_path)

        print("Zipped all logs file into /zip_logs folder.")

    except Exception:
        print("Error while trying to zip old log files.")

def normalize_result(result: dict):
    """
    Helps normalize results of process_site
    """
    clean = {}

    for col in RAW_OUTPUT_CSV_COLUMNS:
        v = result.get(col, None)

        # convert nested objects → JSON string
        if isinstance(v, (list, dict, tuple)):
            clean[col] = json.dumps(v, ensure_ascii=False)
        else:
            clean[col] = v

    return clean
