"""
Configuration file for selectors used during ATLAS scrapping
"""

"""
Passkeys selectors for detecting buttons triggering WebAuthn/passkeys/FIDO2.

Sources:
- https://www.w3.org/TR/webauthn-2/
- https://fidoalliance.org/passkeys/
- https://developer.apple.com/documentation/authenticationservices/asauthorizationcontroller
- https://docs.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/hello-overview
"""
PASSKEY_BUTTON_SELECTORS = [
    # English
    "text=/continue.*passkey/i", "text=/log.*passkey/i",
    "text=/sign.*passkey/i", "text=/use.*passkey/i",
    "text=/passkey/i", "text=/pass key/i", "text=/use security key/i",
    "text=/security key/i", "text=/sign.*device/i",
    "text=/use your device/i", "text=/continue with device/i",
    "text=/continue with security key/i", "text=/use biometrics/i",
    "text=/use face id/i", "text=/use touch id/i",
    "text=/windows hello/i", "text=/next/i",

    # Generic HTML attributes (languages independent)
    "button[aria-label*='passkey']", "button[aria-label*='security key']",
    "button[aria-label*='clé']", "button[aria-label*='schlüssel']",
    "button[aria-label*='sleutel']", "button[aria-label*='nyckel']",
    "button[aria-label*='nøgle']", "button[aria-label*='nøkkel']",
    "button[aria-label*='avain']", "button[aria-label*='Continue with Passkey']",
    "button[aria-label*='Sign in with Passkey']", "button[aria-label*='Signin with Passkey']",

    "button[data-action='login-passkey']", "button[data-testid='passkey-login']",
    "button[onclick*='webauthn']", "button[id*='passkey']",
    "button[class*='passkey']", "button[class*='webauthn']",
    "button[id*='passkey-login-btn']", "button[id*='fido-auth-btn']", "button[id*='passkeyBtn']",
    "text=/passwordless sign in/i",

    # French
    "text=/clé de sécurité/i", "text=/utiliser la clé de sécurité/i",
    "text=/connexion avec clé/i", "text=/se connecter avec.*clé/i",
    "text=/continuer avec.*clé/i", "text=/utiliser votre appareil/i",
    "text=/se connecter avec appareil/i", "text=/connexion biométrique/i",
    "text=/utiliser les données biométriques/i", "text=/touch id/i",
    "text=/face id/i", "text=/suivant/i",  "text=/utiliser une clé d'accès/i",


    # Spanish
    "text=/llave de seguridad/i", "text=/usar llave de seguridad/i",
    "text=/iniciar sesión con.*llave/i", "text=/continuar con.*llave/i",
    "text=/usar tu dispositivo/i", "text=/iniciar sesión con dispositivo/i",
    "text=/usar biometría/i",

    # Portuguese
    "text=/chave de segurança/i", "text=/usar chave de segurança/i",
    "text=/entrar com.*chave/i", "text=/continuar com.*chave/i",
    "text=/usar seu dispositivo/i", "text=/entrar com dispositivo/i",
    "text=/usar biometria/i",

    # Italian
    "text=/chiave di sicurezza/i", "text=/usa chiave di sicurezza/i",
    "text=/accedi con.*chiave/i", "text=/continua con.*chiave/i",
    "text=/usa il tuo dispositivo/i", "text=/accedi con dispositivo/i",
    "text=/usa dati biometrici/i",

    # German
    "text=/sicherheitsschlüssel/i", "text=/mit.*sicherheitsschlüssel anmelden/i",
    "text=/sicherheitsschlüssel verwenden/i", "text=/mit gerät anmelden/i",
    "text=/gerät verwenden/i", "text=/biometrisch/i",

    # Dutch
    "text=/beveiligingssleutel/i", "text=/veiligheidssleutel/i",
    "text=/inloggen met.*sleutel/i", "text=/ga verder met.*sleutel/i",
    "text=/apparaat gebruiken/i", "text=/inloggen met apparaat/i",
    "text=/biometrisch/i",

    # Swedish
    "text=/säkerhetsnyckel/i", "text=/använd säkerhetsnyckel/i",
    "text=/logga in med.*nyckel/i", "text=/fortsätt med.*nyckel/i",
    "text=/använd enhet/i", "text=/logga in med enhet/i", "text=/biometrisk/i",

    # Danish
    "text=/sikkerhedsnøgle/i", "text=/brug sikkerhedsnøgle/i",
    "text=/log ind med.*nøgle/i", "text=/fortsæt med.*nøgle/i",
    "text=/brug enhed/i", "text=/log ind med enhed/i",
    "text=/biometrisk/i",

    # Norwegian
    "text=/sikkerhetsnøkkel/i", "text=/bruk sikkerhetsnøkkel/i",
    "text=/logg inn med.*nøkkel/i", "text=/fortsett med.*nøkkel/i",
    "text=/bruk enhet/i", "text=/logg inn med enhet/i",
    "text=/biometrisk/i",

    # Finnish
    "text=/turva-avain/i", "text=/käytä turva-avainta/i",
    "text=/kirjaudu.*avaimella/i", "text=/jatka.*avaimella/i",
    "text=/käytä laitetta/i", "text=/kirjaudu laitteella/i",
    "text=/biometrinen/i",

]

"""
List of selectors to catch buttons for 2 steps login.

Sources:
- https://developers.google.com/identity/sign-in/web/reference
- https://learn.microsoft.com/en-us/azure/active-directory/develop/
- https://auth0.com/docs/flows
- https://www.keycloak.org/docs/latest/server_admin/
- https://developer.wordpress.org/reference/functions/wp_login_form/
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Authentication_Testing
"""
STEP_SELECTORS = [
    # Step 1 — IDENTIFIER / EMAIL / USERNAME
    [
        # Provider-specific identifiers
        "#identifierNext",                     # Google
        "#idSIButton9",                        # Microsoft / AzureAD
        "#continue", "#continue-button",        # Amazon, Auth0
        "#idp-discovery-submit",               # Okta
        "#kc-login-next",                      # Keycloak
        "#next_button", "#ap_email_next",      # AWS variants
        "#wp-submit",                           # WordPress (login step may ask username first)

        # Normalised "next" actions
        "[data-action='next']", "[data-step='next']", "[data-testid='next-button']",

        # Localized 'Next' texts
        "button:has-text('Next')", "a:has-text('Next')",
        "button:has-text('Continue')", "a:has-text('Continue')",
        "button:has-text('Suivant')", "a:has-text('Suivant')",
        "button:has-text('Weiter')", "button:has-text('Siguiente')",
        "button:has-text('Avanti')", "button:has-text('Volgende')",
        "button:has-text('Próximo')", "button:has-text('Proximo')",
        "button:has-text('Continuer')",

        # Additional languages
        "button:has-text('Dalej')",        # Polish
        "button:has-text('İleri')",        # Turkish
        "button:has-text('Nästa')",        # Swedish
        "button:has-text('Videre')",       # Norwegian
        "button:has-text('Seuraava')",     # Finnish

        # Generic but login-oriented
        "button:has-text('Continue with')", "button:has-text('Next step')",
        "[role='button']:has-text('Next')", "[role='button']:has-text('Continue')",
    ],

    # STEP 2 — Password / Authentication
    [
        # Provider specific IDs
        "#passwordNext",                     # Google
        "#signInSubmit",                     # AWS
        "#login-submit",                     # Generic ID
        "#kc-login",                         # Keycloak
        "#idSIButton9",                      # Microsoft repeated (can be used for pwd)
        "#wp-submit",                        # WordPress final auth
        ".auth0-lock-submit",                # Auth0

        # Login word variants (English)
        "button:has-text('Sign in')", "a:has-text('Sign in')",
        "button:has-text('Log in')",  "a:has-text('Log in')",
        "button:has-text('Login')",   "a:has-text('Login')",
        "button:has-text('Continue')",
        "[role='button']:has-text('Sign in')",

        # French
        "button:has-text('Se connecter')", "a:has-text('Se connecter')",
        "button:has-text('Connexion')",

        # German
        "button:has-text('Anmelden')", "button:has-text('Einloggen')",

        # Spanish
        "button:has-text('Iniciar sesión')", "button:has-text('Acceder')",

        # Italian
        "button:has-text('Accedi')",

        # Dutch
        "button:has-text('Inloggen')", "button:has-text('Aanmelden')",

        # Portuguese
        "button:has-text('Entrar')", "button:has-text('Iniciar sessão')",

        # Nordics
        "button:has-text('Logga in')",     # Swedish
        "button:has-text('Log ind')",      # Danish
        "button:has-text('Logg inn')",     # Norwegian
        "button:has-text('Kirjaudu')",     # Finnish

        # Generic but login-oriented
        "button:has-text('Continue with password')",
        "button:has-text('Verify')", "button:has-text('Submit')",
        "[role='button']:has-text('Submit')",
    ]
]

"""
Basic text for cookie acceptation banner.

Sources:
- https://gdpr-info.eu/art-7-gdpr/
- https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=celex%3A32002L0058
- https://www.w3.org/WAI/consent/
- CMP providers (examples) : OneTrust (https://www.onetrust.com/products/cookie-consent/), Cookiebot (https://www.cookiebot.com/en/)
"""
COOKIE_BANNER_SELECTOR = [
    # Generic one
    'text="OK"', 'text="Oui"', 'text="Yes"', 'text="Si"', 'text="Ja"', 'text="Sim"',

    # French
    'text="Accepter"', 'text="Tout accepter"', 'text="J\'accepte"', 'text="Accepter les cookies"',
    'text="Accepter et continuer"', 'text="Autoriser"', 'text="Autoriser tous les cookies"',

    # English
    'text="Accept all"', 'text="Accept"', 'text="I accept"', 'text="Allow all"', 'text="Allow cookies"',
    'text="Agree"', 'text="Accept cookies"', 'text="Accept and continue"', 'text="Yes, I agree"',
    'text="Only essential"', 'text="Accept necessary"',

    # Spanish
    'text="Aceptar todo"', 'text="Aceptar"', 'text="Estoy de acuerdo"', 'text="Aceptar cookies"',
    'text="Permitir todo"', 'text="Aceptar y continuar"', 'text="Permitir cookies"',

    # Italian
    'text="Accetta tutto"', 'text="Accetto"', 'text="Accetta"', 'text="Accetta i cookie"',
    'text="Accetta e continua"', 'text="Consenti tutti"', 'text="Consenti cookie"',

    # German
    'text="Alle akzeptieren"', 'text="Ich stimme zu"', 'text="Zustimmen"', 'text="Cookies akzeptieren"',
    'text="Akzeptieren"', 'text="Akzeptieren und fortfahren"', 'text="Erlauben Sie alle Cookies"',

    # Protugese
    'text="Aceitar todos"', 'text="Aceito"', 'text="Concordo"', 'text="Permitir todos"',
    'text="Aceitar cookies"', 'text="Aceitar e continuar"', 'text="Permitir cookies"',

    # Dutch
    'text="Alles accepteren"', 'text="Accepteren"', 'text="Ik ga akkoord"', 'text="Cookies toestaan"',
    'text="Sta alle cookies toe"', 'text="Accepteer alle cookies"',
]

"""
Selector button possibilities for iFrame cookie consent

Sources:
- https://www.onetrust.com/products/cookie-consent/
- https://www.didomi.io/cookie-consent/
- https://www.trustarc.com/consent-management/
- https://gdpr-info.eu/art-7-gdpr/
- https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=celex%3A32002L0058
- https://www.w3.org/WAI/consent/
"""
CONSENT_SELECTORS = [
    "button#onetrust-accept-btn-handler",
    "button.didomi-accept-button", "button.trustarc-accept",
    "button[data-testid='uc-accept-all-button']",
    "button[title='Accept all']", "button[class*='accept']",
]

"""
Login button selectors for automatic navigation.

Sources:
- https://playwright.dev/docs/selectors
- https://www.w3.org/TR/wai-aria-1.2/
- https://www.selenium.dev/documentation/webdriver/elements/
"""
LOGIN_SELECTORS = [
    # 1. Universal labels
    "text=Login", "text=Log in", "text=Sign in", "text=Continue",
    "text=Next", "text=Proceed",

    "button:has-text('Login')", "button:has-text('Log in')",
    "button:has-text('Sign in')", "button:has-text('Continue')",
    "button:has-text('Next')", "button:has-text('Proceed')",

    "a:has-text('Login')", "a:has-text('Log in')", "a:has-text('Sign in')",
    'a:has-text("Account")', 'button:has-text("Account")',
    '#login-button', '.login-link', 'text=/sign.?in/i', 'text=/log.?in/i',
    'text=/login/i', 'text=/signin/i', '[data-testid*="login"]',
    '[data-testid*="signin"]', '[aria-label*="login"]',
    '[aria-label*="sign in"]',

    "role=button >> text=Login", "role=button >> text=Log in", "role=button >> text=Sign in",

    # 2. French
    "text=Connexion", "text=Se connecter", "text=S’identifier",
    "text=S'identifier", "text=Continuer",

    "button:has-text('Connexion')", "button:has-text('Se connecter')",
    "button:has-text(\"S’identifier\")", "button:has-text(\"S'identifier\")",

    "a:has-text('Connexion')", "a:has-text('Se connecter')",

    "role=button >> text=Connexion", "role=button >> text=Se connecter",

    # 3. Spanish
    "text=Iniciar sesión", "text=Iniciar sesion",
    "text=Acceder", "text=Identificarse", "text=Continuar",

    "button:has-text('Iniciar sesión')", "button:has-text('Iniciar sesion')",
    "button:has-text('Acceder')", "button:has-text('Identificarse')",

    "a:has-text('Iniciar sesión')", "a:has-text('Acceder')",

    # 4. German
    "text=Anmelden", "text=Einloggen", "text=Weiter",

    "button:has-text('Anmelden')", "button:has-text('Einloggen')",
    "button:has-text('Weiter')",

    "a:has-text('Anmelden')", "a:has-text('Einloggen')",

    # 5. Italian
    "text=Accedi", "text=Accedere", "text=Continua",

    "button:has-text('Accedi')", "a:has-text('Accedi')",

    # 6. Portuguese
    "text=Entrar", "text=Acessar", "text=Iniciar sessão",
    "text=Iniciar sessao", "text=Continuar",

    "button:has-text('Entrar')", "button:has-text('Acessar')",
    "button:has-text('Iniciar sessão')",

    "a:has-text('Entrar')", "a:has-text('Iniciar sessão')",

    # 7. Dutch
    "text=Inloggen", "text=Aanmelden", "text=Doorgaan",

    "button:has-text('Inloggen')", "button:has-text('Aanmelden')",
    "a:has-text('Inloggen')",

    # 8. Nordics
    "text=Logga in",      # Swedish
    "text=Log ind",       # Danish
    "text=Logg inn",      # Norwegian
    "text=Kirjaudu sisään", # Finnish

    "button:has-text('Logga in')", "button:has-text('Log ind')",
    "button:has-text('Logg inn')", "button:has-text('Kirjaudu sisään')",

    # 9. SSO / OAUTH / OIDC / SAML
    "text=Sign in with", "text=Continue with", "text=Use your account",
    "text=Corporate login", "text=SSO Login", "text=Single Sign-On",

    "button:has-text('Sign in with')", "button:has-text('Continue with')",
    "button:has-text('Corporate login')",

    # Auth0
    "text=Continue with Auth0", "button:has-text('Continue with Auth0')",

    # Okta
    "text=Sign in to your account", "button:has-text('Sign in to your account')",

    # Azure AD
    "text=Sign in to your organization",
    "button:has-text('Sign in to your organization')",

    # Google SSO
    "text=Sign in with Google",

    # 10. IdP Flavours (enterprise)
    "text=IdP Login", "text=Identity Provider Login",

    "button:has-text('IdP Login')", "button:has-text('Identity Provider Login')",
]

AVATAR_LOGIN_SELECTORS = [
    # ARIA labels (most reliable)
    '[aria-label*="account" i]', '[aria-label*="profile" i]',
    '[aria-label*="user" i]', '[aria-label*="login" i]',
    '[aria-label*="sign in" i]', '[aria-label*="log in" i]',
    '[aria-label*="my account" i]',
    '[aria-label*="compte" i]',      # French
    '[aria-label*="profil" i]',      # French
    '[aria-label*="konto" i]',       # German
    '[aria-label*="cuenta" i]',      # Spanish
    '[aria-label*="accedi" i]',      # Italian

    # Title attributes (tooltips)
    '[title*="account" i]', '[title*="profile" i]', '[title*="user" i]',
    '[title*="login" i]', '[title*="sign in" i]',

    # Common IDs
    '#account-icon', '#user-icon', '#profile-icon', '#login-icon',
    '#account-menu', '#user-menu', '#profile-menu', '#nav-account',
    '#nav-user', '#header-account', '#header-user',
    '#nav-link-accountList',

    # Common classes
    '.account-icon', '.user-icon', '.profile-icon', '.login-icon',
    '.account-button', '.user-button', '.nav-account', '.nav-user',
    '.header-account', '.header-user', '.customer-account', '.account-toggle',
    '.user-toggle',

    # Font Awesome icons
    '.fa-user', '.fa-user-circle', '.fa-user-alt', '.far.fa-user',
    '.fas.fa-user', '.fa-user-cog',

    # Material Icons
    'button:has(.material-icons:has-text("person"))',
    'button:has(.material-icons:has-text("account_circle"))',
    'a:has(.material-icons:has-text("person"))',

    # SVG-based
    'svg[class*="user" i]', 'svg[class*="account" i]',
    'svg[class*="profile" i]', 'button:has(svg[class*="user" i])',
    'button:has(svg[class*="account" i])', 'a:has(svg[class*="user" i])',
    'a:has(svg[class*="account" i])',

    # Data attributes (testing frameworks, React, etc.)
    '[data-testid*="account" i]', '[data-testid*="user" i]',
    '[data-testid*="profile" i]', '[data-testid*="login" i]',
    '[data-cy*="account" i]', '[data-cy*="user" i]',

    # Header navigation
    'header button[class*="account" i]', 'header button[class*="user" i]',
    'header a[class*="account" i]', 'header a[class*="user" i]',
    'nav button[class*="account" i]', 'nav button[class*="user" i]',
    'nav a[class*="account" i]', 'nav a[class*="user" i]',

    # Role-based with icons
    '[role="button"]:has(.fa-user)', '[role="button"]:has(svg[class*="user"])',
    '[role="link"]:has(.fa-user)',
]

"""
Language-related keywords commonly found in language-selection
or locale-suggestion popups that appear before or during authentication flows.

These popups can block access to the actual login UI and must be dismissed
to reach authentication-related elements (password fields, passkeys, etc.).

Sources:
- Manual observation of large commercial websites (e-commerce, SaaS, hosting)
- Shopify, Stripe, Adobe, Google, Microsoft locale dialogs
- Common CMP / locale UX patterns (Baymard Institute, UX Collective)
"""
LANGUAGE_HINTS = [
    # English
    "english", "en",

    # French
    "français", "fr",

    # German
    "deutsch", "de",

    # Spanish
    "español", "es",

    # Italian
    "italiano", "it",

    # Generic confirmation / language-related actions
    "continue",
    "confirm",
    "ok",
    "language"
]

"""
Keywords indicating a *negative* or *dismissive* user action in modal dialogs,
such as:
- "Do not change language"
- "Keep current settings"
- "Cancel"
- "Stay on current site"

Sources:
- Empirical analysis of language/cookie popups on:
  Google, Cloudflare, Shopify-hosted stores, SaaS dashboards
- UX best practices for consent and preference dialogs
- GDPR/CMP patterns (IAB Europe TCF UI observations)
"""
NEGATIVE_ACTION_HINTS = [
    # English
    "no", "don't", "do not", "keep", "stay", "cancel",

    # French
    "non", "ne pas", "annuler"
]

"""
CSS selectors targeting common login entry points when no explicit
"Login" or "Sign in" text is present.

This is especially important for modern websites where:
- Login is represented by an icon (user/avatar silhouette),
- The label is only accessible via aria-label or title attributes,
- The login action opens a modal instead of navigating to a page.

Sources:
- WAI-ARIA Authoring Practices (W3C)
  https://www.w3.org/TR/wai-aria-practices/
"""
LOGIN_ICON_SELECTORS = [
    # Accessible buttons (recommended by WAI-ARIA)
    "button[aria-label*='login']", "button[title*='login']",

    # Account / user related ARIA
    "button[aria-label*='account']", "button[aria-label*='sign']",
    "button[aria-label*='profile']", "button[aria-label*='user']",

    "a[aria-label*='account']", "a[aria-label*='profile']",
    "a[aria-label*='sign']",

    # Common class-based patterns
    ".header-login-icon", ".login-button",

    # Fallback: login links
    "a[href*='login']",

    # SVG-based avatar icons
    "button svg[aria-label*='user']", "button svg[aria-label*='account']",
    "button svg[aria-label*='profile']",

    "button:has(svg)", "a:has(svg)",

    # Common avatar / account class names
    ".account", ".user", ".profile", ".avatar",

    ".user-menu", ".account-menu", ".profile-menu",
]
