"""
Configuration file for keywords used during ATLAS scrapping
"""

"""
List of typical keywords found in console logs and related to FedCM or Google Sign-In (GSI).

Sources:
- https://developers.chrome.com/docs/privacy-sandbox/fedcm
- https://github.com/fedidcg/FedCM
- https://developers.google.com/identity/gsi/web
- https://developers.google.com/identity/one-tap/web
- https://chromestatus.com/feature/5174308356057088
- https://fedidcg.github.io/FedCM
"""
FEDCM_LOG_KEYWORDS = [
    "FedCM", "GSI_LOGGER", "One Tap", "disable FedCM", "Identity Provider", "IdP"
]

"""
Potential login keywords

Sources:
- https://auth0.com/docs/authenticate/login
- https://developer.okta.com/docs/guides/oie-embedded-widget-use-case-basic-sign-in/
- https://developers.google.com/identity
- https://learn.microsoft.com/entra/identity/authentication/concept-authentication
- https://www.nngroup.com/articles/login-registration/
- https://www.w3.org/WAI/WCAG21/Understanding/accessible-authentication
"""
LOGIN_KEYWORDS = [
    # English
    "login", "log in", "log-in", "logon", "log on", "log-on",
    "sign in", "sign-in", "signin", "sign on", "sign-on",
    "account login", "access account", "my account", "member login",
    "continue with",  "proceed to login", "authenticate", "play",
    "Sign up", "log in / sign up", "login / sign up", "personal area",
    "personnal area", "Account", "client area", "customer area", "member login", "sign up/login",

    # French
    "connexion", "se connecter", "s’identifier", "s'identifier",
    "connectez-vous", "je me connecte",
    "me connecter", "accéder à mon compte",
    "identifiez-vous", "mon compte", "accéder au compte",
    "aller à la connexion", "espace client", "authentification",
    "espace clients", "Jouer", "Compte", "m'identifier", "m'authentifier", "mon espace",
    "espace personnel"

    # Spanish
    "iniciar sesión", "inicia sesión", "iniciar sesion",
    "acceder", "acceso", "entrar", "identificarse", "mi cuenta",
    "acceda a su cuenta", "ingresar", "Área cliente",

    # German
    "anmelden", "einloggen", "loggen sie sich ein", "konto anmelden",
    "mein konto", "zugang", "einloggen", "zum login",
    "mein konto", "zugang", "einloggen", "zum login",

    # Italian
    "accedi", "accedere", "accesso", "entra", "entra nel tuo account",
    "il mio account", "accedi al tuo account",

    # Portuguese (Brazil + Portugal unified)
    "entrar", "fazer login", "iniciar sessão", "acessar", "acesso",
    "minha conta", "entrar na conta", "acessar conta",

    # Dutch
    "inloggen", "aanmelden", "meld je aan", "login", "mijn account", "toegang",

    # Swedish
    "logga in", "logga på", "min sida",

    # Danish
    "log ind", "log på", "min konto",

    # Norwegian
    "logg inn", "logg på", "min konto",

    # Multilingual patterns
    "continue", "verify identity", "パスワードでログイン", "ユーザー登録は"
    "continue", "verify identity", "パスワードでログイン", "ユーザー登録は"
]

"""
User interface keywords in multi language (most common ones, at least).

Sources:
- https://fidoalliance.org/specs/fido-v2.2-id-20210930/
- https://www.w3.org/TR/webauthn-2/
- https://developer.apple.com/passkeys/
- https://developers.google.com/identity/passkeys
- https://developers.yubico.com/WebAuthn/
- https://auth0.com/docs/authenticate/passwordless
- https://learn.microsoft.com/windows/security/identity-protection/hello-for-business/hello-identity-verification
- https://developer.apple.com/documentation/localauthentication
"""
UI_KEYWORDS = [
    # 1. English
    "passkey", "passkeys", "use a passkey", "use your passkey",
    "sign in with a passkey", "sign in with passkey", "log in with a passkey",
    "login with passkey", "log in with passkey", "continue with a passkey",

    "security key", "security keys", "your security key", "hardware key", "usb security key",

    "FIDO", "FIDO2", "WebAuthn", "authenticator device", "authentication device",
    "device authenticator", "device-based login",

    "passwordless", "sign in without password", "password-free login", "passwordless authentication",
    "use your device", "use device authentication",

    "biometric login", "use biometrics", "face unlock", "device unlock",

    "touch to sign in", "tap to sign in", "use your phone to sign in", "sign in with your phone",

    # 2. French
    "clé de sécurité", "clés de sécurité", "clé fido", "clé fido2", "clé weauthn",
    "clé d'authentification", "clé usb de sécurité", "clé d'accès", "périphérique de sécurité",

    "passkey", "passkeys", "se connecter avec une passkey", "utiliser une passkey",

    "connexion sans mot de passe", "authentification sans mot de passe",
    "authentification forte", "authentification renforcée",
    "identification sans mot de passe",

    "utiliser votre appareil", "utiliser un appareil sécurisé",
    "authentification par appareil", "connexion par appareil",

    "connexion biométrique", "empreinte digitale", "reconnaissance faciale",
    "toucher pour se connecter",

    # 3. German
    "sicherheitsschlüssel", "sicherheitsschluessel", "fido", "fido2", "webauthn",
    "passkey verwenden", "passkeys verwenden",

    "kennwortlos", "anmeldung ohne passwort", "passwortloses login", "passwortlose anmeldung",

    "gerät verwenden", "mit gerät anmelden",
    "biometrische anmeldung", "fingerabdruck", "gesichtserkennung",

    # 4. Spanish
    "clave de seguridad", "clave seguridad", "llave de seguridad", "llave fido",

    "usar passkey", "usar una passkey",
    "iniciar sesión con passkey", "inicio de sesión sin contraseña",

    "autenticación sin contraseña", "inicio sin contraseña",
    "inicio de sesión biométrico", "usar biometría",

    "usar dispositivo", "autenticación por dispositivo",

    # 5. Italian
    "chiave di sicurezza", "chiave sicurezza", "chiave fido", "chiave fido2",

    "usa passkey", "utilizza una passkey",
    "accesso senza password", "autenticazione senza password",

    "usa il dispositivo", "accedi con dispositivo",
    "accesso biometrico", "impronta digitale", "riconoscimento facciale",

    # 6. Portugese
    "chave de segurança", "chave segurança", "chave fido", "webauthn",

    "usar passkey", "usar uma passkey", "login sem senha", "acesso sem senha",
    "autenticação sem senha",

    "usar dispositivo", "entrar com dispositivo",
    "autenticação biométrica", "impressão digital", "reconhecimento facial",

    # 7. Dutch
    "beveiligingssleutel", "beveiligings sleutel",

    "passkey gebruiken", "gebruik passkey",
    "inloggen zonder wachtwoord", "wachtwoordloos inloggen",

    "apparaat gebruiken", "inloggen met apparaat",
    "biometrisch inloggen", "vingerafdruk", "gezichtsherkenning",

    # 8. SSO / Enterprise / IdP Keywords
    "security key or passkey", "use a security key or passkey",
    "sign in with your device", "use your authenticator",
    "use your security device", "strong authentication", "hardware token", "security token",
    "touch your key", "tap your key",

    # Okta specific
    "use your security key", "use your biometric authenticator",

    # Auth0 / OAuth2 flows
    "touch your security key", "use a connected device", "verify with your device",

    # Azure AD
    "sign in with Windows Hello", "windows hello",

    # 9. Mobile-Specific UI keywords (Android / iOS passkey prompts)
    "use screen lock", "use device unlock", "use face id", "use touch id",
    "continue with face id", "continue with touch id",
]

"""
Detect the presence of elements related to FIDO2/WebAuthn in visible DOM, shadow DOM, storages, ...

Sources:
- https://fidoalliance.org/specs/fido-v2.2-id-20210930/
- https://www.w3.org/TR/webauthn-2/
- https://developer.apple.com/passkeys/
- https://developers.google.com/identity/passkeys
- https://developers.yubico.com/WebAuthn/
- https://auth0.com/docs/authenticate/passwordless
- https://learn.microsoft.com/windows/security/identity-protection/hello-for-business/hello-identity-verification
- https://developer.apple.com/documentation/localauthentication
"""
FIDO_KEYWORDS = [
    # 1. English
    "fido", "fido2", "webauthn", "passkey", "passkeys", "security key",
    "security keys", "hardware key", "hardware security key", "hardware token", "security token",
    "yubikey", "yubi key", "yubico",

    "authenticator", "device authenticator", "platform authenticator", "roaming authenticator",
    "biometric", "biometrics",

    "face unlock", "faceid", "face id", "fingerprint", "touch id", "windows hello",

    "device-bound credential", "private key", "passwordless", "passwordless authentication",
    "strong authentication", "phishing-resistant authentication",

    # 2. French
    "clé de sécurité", "clés de sécurité", "clé fido", "clé fido2", "clé physique", "clé matérielle",

    "authentificateur", "authentificateur d'appareil", "authentificateur matériel",

    "biométrique", "authentification biométrique", "reconnaissance faciale", "empreinte digitale",

    "token matériel", "jeton matériel", "authentification forte", "sans mot de passe",

    # 3. German
    "sicherheitsschlüssel", "sicherheitsschluessel", "fido", "fido2", "webauthn",
    "hardware-token", "sicherheitstoken",

    "authentifikator", "geräteauthentifikator", "plattformauthentifikator", "roaming-authentifikator",

    "biometrisch", "gesichtserkennung", "fingerabdruck", "passwortlos", "starke authentifizierung",

    # 4. Spanish
    "clave de seguridad", "llave de seguridad", "llave fido", "llave fido2", "token de hardware",
    "autenticador", "autenticador de dispositivo",

    "biométrico", "autenticación biométrica", "reconocimiento facial", "huella dactilar",

    "autenticación sin contraseña", "autenticación fuerte",

    # 5. Italian
    "chiave di sicurezza", "chiave sicurezza", "chiave fido", "chiave fido2", "token hardware",

    "autenticatore", "autenticatore dispositivo",

    "biometrico", "autenticazione biometrica", "riconoscimento facciale", "impronta digitale",

    "autenticazione senza password", "autenticazione forte",

    # 6. Dutch
    "beveiligingssleutel", "beveiligings sleutel",  "hardwaretoken", "beveiligingstoken",

    "authenticator", "apparaat-authenticator", "platformauthenticator", "roamingauthenticator",

    "biometrisch", "gezichtsherkenning", "vingerafdruk", "wachtwoordloos", "sterke authenticatie",

    # 7. Portuguese
    "chave de segurança", "chave segurança",
    "chave fido", "chave fido2", "token de hardware",

    "autenticador", "autenticador de dispositivo",

    "biométrico", "autenticação biométrica", "reconhecimento facial", "impressão digital",

    "autenticação sem senha", "autenticação forte",

    # 8. Enterprise / IdP / SSO-Specific terms
    # (Okta, Duo, AzureAD, Google Workspace, Auth0)
    "security key or passkey", "fido security key", "phishing resistant",
    "phishing resistant authentication", "strong device credential",
    "fido authenticator", "touch your security key", "tap your key",
    "insert your security key", "use your authenticator", "verify with security key",

    # 9. Mobile-Specific Terms (iOS / Android)
    "device unlock", "screen lock", "android biometric", "android biometrics",
    "use device security",

    # could this work?
    "パスキーでログイン"

    # could this work?
    "パスキーでログイン"
]

"""
Keywords for iFrame cookie consent

Sources:
- https://eur-lex.europa.eu/eli/reg/2016/679/oj
- https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32002L0058
"""
CONSENT_KEYWORDS = [
    # English
    "accept cookies", "cookie consent", "we use cookies", "manage cookies",
    "cookie preferences", "consent", "your privacy", "allow cookies",

    # French
    "accepter les cookies", "nous utilisons des cookies", "préférences de cookies",
    "gestion des cookies", "paramètres de cookies", "votre vie privée", "autoriser les cookies",

    # Spanish
    "aceptar cookies", "usamos cookies", "gestionar cookies", "preferencias de cookies",
    "su privacidad", "permitir cookies",

    # Italian
    "accetta i cookie", "utilizziamo i cookie", "gestione dei cookie", "preferenze sui cookie",
    "consenso ai cookie", "la tua privacy",

    # German
    "cookies akzeptieren", "wir verwenden cookies", "cookie einstellungen",
    "cookie richtlinie", "ihre privatsphäre", "zustimmung cookies",

    # Portuguese
    "aceitar cookies", "usamos cookies", "preferências de cookies",
    "configurações de cookies", "consentimento de cookies", "sua privacidade",

    # Dutch
    "cookies accepteren", "wij gebruiken cookies", "cookie-instellingen", "cookie voorkeuren",
    "je privacy", "toestemming cookies",
]

"""
List of OTP keywords.

Source:
- https://pages.nist.gov/800-63-3/sp800-63b.html
"""
OTP_KEYWORDS = [
    # English
    "otp", "OTP", "one time password", "one-time password", "oneTimePassword",
    "verification code", "auth code", "security code", "2fa", "2FA",
    "two factor", "two-factor", "two-step verification", "two step verification",
    "sms code", "email code", "app code", "verification pin", "verification PIN",
    "enter code", "input code", "receive code", "code sent", "code received",
    "temporary password", "temp password", "passcode", "authenticator code",

    # French
    "mot de passe à usage unique", "mot de passe temporaire", "code de vérification",
    "code sms", "code de sécurité", "authentification à deux facteurs",
    "vérification en deux étapes", "saisir le code", "envoyé par sms", "code reçu",
    "code temporaire", "passcode", "code d'authentification",

    # Spanish
    "contraseña de un solo uso", "contraseña temporal", "código de verificación",
    "código de seguridad", "código sms", "autenticación en dos pasos", "autenticación de dos factores",
    "2fa", "introducir código", "clave temporal", "enviado por sms", "código recibido",
    "codigo temporal", "passcode", "código de autenticación",

    # German
    "einmalpasswort", "einmal-passwort", "prüfcode", "sicherheitscode",
    "verifizierungscode", "sms-code", "zweifaktor", "zwei-schritt-verifizierung",
    "code eingeben", "per sms gesendet", "temporäres passwort", "passcode",
    "authentifizierungscode",

    # Italian
    "password monouso", "codice di verifica", "codice di sicurezza",
    "codice sms", "autenticazione a due fattori","verifica in due passaggi",
    "inserisci il codice", "inviato via sms", "password temporanea", "codice temporaneo", "passcode", "codice di autenticazione",

    # Portuguese
    "senha única", "senha de uso único", "senha temporária",
    "código de verificação", "código de segurança", "código sms",
    "autenticação em dois fatores", "verificação em duas etapas",
    "insira o código", "enviado por sms", "código recebido", "código temporário",
    "passcode", "código de autenticação",

    # Dutch
    "eenmalig wachtwoord", "verificatiecode", "beveiligingscode",
    "sms-code", "tweeledige verificatie", "verificatie in twee stappen",
    "code invoeren", "verzonden via sms", "tijdelijk wachtwoord", "passcode",
    "authenticatiecode"
]

"""
List of keywords to check if a page is actually a login page or not.
"""
LOGIN_PAGE_KEYWORDS = [
    "login", "log in", "log-in", "logon", "log on", "log-on", "sign in",
    "sign-in", "signin", "sign on", "sign-on", "continue with",
    "authenticate", "continue", "Sign up", "log in / sign up",
    "login / sign up","sign up/login",

    " connexion ", " se connecter ", " connexion ", " connexion ",
    " connexion ", " connexion ", " s'inscrire ", " inscription ",
    " inscription ", " s'inscrire ", " inscription ", " continuer avec ",   " s'authentifier ", " continuer ", " se connecter / s'inscrire ",
    " connexion / inscription ", " inscription / connexion ",

    "Anmelden", "Einloggen", "Login", "weitermachen", "weiter",

    "iniciar sesión", "iniciar", "iniciar sesión",  "iniciar sesión",
    "iniciar sesión", "iniciar sesión",

    "registrarse", "continuar con",   "autenticar", "continuar", "iniciar sesión/registrarse", "iniciar sesión/registrarse", "registrarse/iniciar sesión",

    "logga in", "logga på", "min sida", "log ind", "log på", "min konto", "logg inn", "logg på", "min konto"
]
