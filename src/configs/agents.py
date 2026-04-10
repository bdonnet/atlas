"""
Configuration file for user agents used during ATLAS scrapping
"""

"""
It is possible that some web sites filter playwright/chromium/selenium headless browser.

Sources:
- https://developer.chrome.com/blog/user-agent-reduction/
- https://developer.chrome.com/blog/chrome-101-device/
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent/Firefox
- https://wiki.mozilla.org/Gecko_user_agent_string_reference
- https://wicg.github.io/ua-client-hints/
- https://www.iana.org/time-zones/
- https://cldr.unicode.org/
"""
USER_AGENTS_POOL = [
    {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "locale": "en-US",
        "platform": "Windows",
        "viewport": {"width": 1280, "height": 720},
        "timezone": "America/New_York"
    },
]
