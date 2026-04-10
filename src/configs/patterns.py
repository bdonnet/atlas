"""
Configuration file for patterns used during ATLAS scrapping
"""

"""
JS keywords and functional patterns allowing to detect any support of passkey/WebAuthn on the client side.

Those keywords are used to analyze scripts loaded in the page (i.e., <script src=...> or inline code) for identifying the website technical capability to propose passkeys.
"""
PASSKEY_JS_KEYWORDS = [
    # WebAuthn core
    "webauthn", "publickeycredential", "navigator.credentials",
    "credentials.create", "credentials.get",

    # Passkey-specific
    "passkey", "passkeys", "ispasskeysupported", "passkeyavailable",

    # Registration / setup flows
    "passkey/setup", "passkey/register", "passkey/enroll",
    "passkey/create",

    # Authentication / assertion
    "passkey/authenticate", "passkey/assert", "passkey/login",

    # Optional / deferred flows
    "passkey/skip", "skip-passkey", "passkey_optional",

    # Platform capability checks
    "isconditionalmediationavailable", "conditionalmediation",
    "authenticatorattachment", "platformauthenticator",

    # Vendor / IdP conventions
    "fido", "fido2",
]

"""
Detects endpoints involved in authentication relying on a shared secret (password).
"""
PASSWORD_ENDPOINT_PATTERNS = [
    r"/password",
    r"/login",
    r"/authenticate",
    r"/oauth/.*/password",
]

"""
Detects effective usage of WebAuthn/FIDO2 during session.
"""
WEBAUTHN_ENDPOINT_PATTERNS = [
    r"/webauthn",
    r"/assertion",
    r"/attestation",
]

"""
Detects the presence of or APIs call related to passkeys registration or activation.
"""
PASSKEY_SETUP_PATTERNS = [
    r"/passkey/setup",
    r"/passkey/register",
    r"/passkey/skip",
]

"""
List of known IdP potentially supporting FedCM or FIDO2.

Sources:
- https://fedidcg.github.io/FedCM/
- https://developers.google.com/identity/fedcm
"""
KNOWN_FEDCM_IDPS = [
    "google", "apple", "facebook", "meta", "github", "microsoft",
    "linkedin", "okta", "auth0", "salesforce", "twitter", "amazon", "yahoo", "dropbox"
]

"""
WebAuthn patterns.  Keywords indicating WebAuthn/FIDO2/passkeys usage.

This list is heuristically built.

Sources:
- https://www.w3.org/TR/webauthn-3
- https://fidoalliance.org/specifications/
- https://developers.google.com/identity/passkeys
- https://developer.apple.com/passkeys/
- https://learn.microsoft.com/windows/security/passkeys/
"""
WEBAUTHN_PATTERNS = [
    # Core WebAuthn / FIDO2 keywords
    "webauthn", "fido2", "fido", "passkey", "credential", "authenticator", "security key",
    "passwordless", "device credential", "uv=", "user verification",

    # Navigator APIs
    "navigator.credentials.create", "navigator.credentials.get", "publicKey",
    "clientDataJSON", "attestationObject", "authenticatorData", "signature", "userHandle",
    "rpId", "allowCredentials", "challenge", "timeout", "attestation",

    # Endpoints / REST patterns observed
    "/attestation", "/assertion", "/makeCredential", "/getAssertion",
    "/register", "/registration", "/signin", "/login", "/authenticate", "/authenticator",
    "/begin", "/complete", "/finish", "/callback", "/challenge",
    "/webauthn/register", "/webauthn/login", "/webauthn/assertion", "/webauthn/attestation",
    "/fido2/assertion", "/fido2/attestation", "/fido/assertion", "/fido/attestation",
    "/webauthn/begin", "/webauthn/finish", "/fido2/begin", "/fido2/finish",

    # Frameworks / SDKs / libraries
    "passkeys", "ctap2", "security-key", "hardware-key", "key-registration",
    "yubico", "yubikey", "webAuthn.io", "passkey.io", "apple-passkey", "google-passkey",
    "webauthn-lib", "fido2-lib", "simplewebauthn", "webauthn4j", "webauthn-server",

    # Common query parameters
    "user_id", "username", "sessionId", "clientDataJSON", "attestationObject",
    "authData", "signature", "credentialId", "authenticatorId",

    # Variants / casing
    "webauthn.js", "fido2.js", "passkey.js", "navigator.Credentials.create", "navigator.Credentials.get"
]

"""
Password patterns.  Keywords frequently used for identifying fields or flow
related to authentication/passwords/login/reset/password change.

This list is heuristic based.  It aims at covering a maximum aount of common/standard
cases but does not guarantee to detect password/login field that has been personalized

Sources:
- https://developer.mozilla.org/fr/docs/Web/HTML/Reference/Elements/input/password
- https://www.chromium.org/developers/design-documents/form-styles-that-chromium-understands
"""
PASSWORD_PATTERNS = [
    # Generic password/auth keywords
    "password", "pwd", "pass", "passwd", "credential", "credentials",
    "auth", "authenticate", "authentication", "authorize", "authorization",
    "login", "signin", "sign-in", "sign_in", "signon", "sign-on", "sign_on",
    "logout", "signout", "sign-out", "sign_out",
    "reset", "forgot", "forgot-password", "forgot_password", "reset-password", "reset_password",
    "change-password", "change_password", "update-password", "update_password",

    # Tokens / sessions / cookies
    "token", "access_token", "refresh_token", "session", "csrf", "xsrf", "sessionId",
    "authToken", "bearerToken",

    # User identifiers / payload fields
    "user", "username", "user_id", "email", "identifier", "login_id", "account", "profile",
    "uid", "userName", "userEmail",

    # Common API endpoints
    "/api/login", "/api/signin", "/api/auth", "/api/session", "/api/token",
    "/api/authenticate", "/api/login_check",
    "/user/login", "/user/auth", "/users/login", "/users/authenticate",
    "/auth/login", "/auth/signin", "/auth/token", "/auth/session",
    "/session/create", "/session/new", "/session/start", "/session/init",
    "/account/login", "/account/authenticate", "/account/session",
    "/customer/login", "/member/login", "/admin/login", "/portal/login",

    # Frameworks / SSO / OAuth / OpenID
    "oauth", "openid", "sso", "basic-auth", "form-login", "jwt", "bearer",
    "oauth2", "oidc", "saml", "saml2", "login/oauth", "login/openid", "login/sso",

    # Variants / casing
    "Password", "Pwd", "PASS", "Login", "SignIn", "SignUp", "SignOn", "LogIn", "Auth", "Authenticate"
]

"""
Sometimes, the login is "hidden" in a particular page (login/, sign/, ...)
This converts URLs from SITES into their (known) particular login pages.

Up to now, this is done manually for a few websites.  Must be completed for the probed URL list
"""
LOGIN_URLS = {
    "https://github.com": "https://github.com/login",
    "https://google.com": "https://accounts.google.com/signin",
    "https://dropbox.com": "https://www.dropbox.com/login",
    "https://notion.so": "https://www.notion.so/login",
    "https://facebook.com": "https://www.facebook.com/login",
    "https://x.com": "https://www.x.com/login",
}

"""
Common paths towards login pages.  The list is built upon heuristics and well known practices.
It aims at covering most likely paths to detect as quickly as possible a login page.

Sources:
- https://laravel.sillo.org/posts/creer-une-application-lauthentification
- https://docs.spring.io/spring-security/site/docs/5.1.0.M1/reference/htmlsingle
- https://docs.aws.amazon.com/cognito/latest/developerguide/managed-login-endpoints.html
"""
COMMON_LOGIN_PATHS = [
    # 1. Global (present across nearly all languages)
    "/login", "/signin", "/sign-in", "/log-in", "/user/signin",

    "/account/login", "/user/login", "/users/login", "/auth/login", "/session/login",
    "/customer/login", "/#/login", "/app/login", "/app/login/",

    # 2. English
    "/account/signin", "/myaccount/login", "/customer/account/login",
    "/profile/login", "/members/login", "/member/login", "/account/access",
    "/access/login", "/login/account", "/login.html", "/signin.html",
    "/login.php", "/sign-in.php", "/index.php?login", "/index.php?signin",
    "app/login",

    # 3. French
    "/connexion", "/utilisateur/connexion", "/compte/connexion",
    "/authentification", "/identification",

    # 4. Spanish
    "/iniciar-sesion",

    # 5. German
    "/anmelden", "/einloggen", "/benutzer/anmeldung",
    "/konto/anmeldung", "/authentifizierung",

    # 6. Italian
    "/accesso", "/accedi",

    # 7. Portugese
    "/entrar", "/acesso",

    # 8. Dutch
    "/inloggen",

    # 9. Swedish
    "/logga-in",

    # 10. Danish
    "/log-ind",

    # 11. Norwegian
    "/logg-inn",

    # 12. Modern frameworks (Next.js, React, Vue, Angular)
    "/api/auth/login", "/api/login", "/auth/local/login",

    # 13. DJANGO
    "/accounts/login", "/users/signin", "/login/",

    # 14. Laravel / Symfony / PHP Frameworks
    "/login/process", "/auth/login/submit",

    # 15. Ruby on Rails
    "/users/sign_in",

    # 16. SSO / OIDC / SAML / IdP Providers
    "/sso/login"
]
"""
Challenges generating endless pages.

Sources:
- https://developers.cloudflare.com/cloudflare-challenges/challenge-types/turnstile/
- https://developers.cloudflare.com/fundamentals/reference/cdn-cgi-endpoint
- https://developers.cloudflare.com/cloudflare-challenges/concepts/how-challenges-work
"""
CF_IGNORE_PATTERNS = (
    # Cloudflare challenge base URLs
    "challenges.cloudflare.com", "cdn-cgi/challenge-platform",
    "cdn-cgi/challenge", "cdn-cgi/trace",

    # Cloudflare anti-bot / TURNSTILE / Managed Challenge
    "turnstile",
    "h/b/",  # human/bot
    "h/c/",  # human/check
    "h/s/",  # human/solve
    "/flow/",
    "/cmg/",  # challenge management gateway

    # Cloudflare: internal blob frames
    "blob:https://challenges.cloudflare.com",
    "blob:https://www.cloudflare.com",

    # hCaptcha used inside Cloudflare challenges
    "hcaptcha.com", "newassets.hcaptcha.com",
    "assets.hcaptcha.com", "blob:https://hcaptcha.com",

    # Blank / internal browser frames
    "about:blank", "chrome-error://", "chrome-extension://",

    # possibly with heavy anti-bot
    "cf-assets", "cf-chl", "cf-turnstile",
)

"""
CSS selector patterns for detecting authentication containers and UI elements.

These patterns are designed for use with JavaScript's querySelector() and work
across different authentication implementations (modal, redirect, iframe, etc.).

Sources:
- WAI-ARIA Authoring Practices (W3C): https://www.w3.org/TR/wai-aria-practices/
- Material Design authentication patterns
- Bootstrap form conventions
- Common SPA framework patterns (React, Vue, Angular)
"""
AUTH_CONTAINER_PATTERNS = [
    # Class-based patterns
    "[class*='login']", "[class*='signin']", "[class*='sign-in']",
    "[class*='auth']", "[class*='authenticate']", "[class*='authentication']",

    # ID-based patterns
    "[id*='login']", "[id*='signin']", "[id*='sign-in']",
    "[id*='auth']", "[id*='authenticate']", "[id*='authentication']",

    # ARIA attributes (accessibility)
    "[aria-label*='login']", "[aria-label*='sign in']",
    "[aria-label*='sign-in']", "[aria-label*='signin']",
    "[aria-label*='auth']", "[aria-label*='authenticate']",
    "[aria-label*='account']", "[aria-label*='user']",
    "[aria-label*='profile']",

    # Data attributes (modern frameworks)
    "[data-testid*='login']", "[data-testid*='signin']",
    "[data-testid*='auth']",
]
