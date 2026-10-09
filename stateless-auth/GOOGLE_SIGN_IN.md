# Google Identity Services sign-in

Google now uses the GIS ID-token flow. The handler verifies RS256 signatures against Google's fixed HTTPS JWKS endpoint, issuer, audience, authorized party, expiration, issued-at, verified email and a server-issued nonce. The Google API client and Jackson HTTP client dependencies are removed. The old Google authorization-code callback is disabled; `googleClientSecret` and `googleRedirectUri` are retained configuration fields but are ignored by this flow.

Deploy with the matching login-view and light-portal changes:

- https://github.com/lightapi/login-view/issues/17
- https://github.com/lightapi/light-portal/issues/865

Configure `google-sign-in.yml` with `allowedOrigin` equal to the exact HTTPS login-view origin, without a trailing slash, and `portalCommandUrl` equal to the HTTPS Portal command endpoint (for example `https://portal.example/portal/command`). Blank `allowedOrigin` disables Google sign-in. A blank command URL uses existing command-service discovery. Set `statelessAuth.googleClientId` to the same OAuth web client ID used by GIS. Configure the bootstrap service token with the Portal-approved client ID, signed host and dedicated `portal.google-identity.w` scope. Never put that token in the browser.

Route `/google` and `/google/link` to `GoogleAuthHandler`. The login origin needs credentialed CORS for POST/OPTIONS, `Content-Type`, and an exact `Access-Control-Allow-Origin` (never `*`). Existing CORS middleware handles OPTIONS. Only the configured Origin may issue challenges or submit credentials.

The browser POSTs `?challenge=1` to obtain a five-minute nonce and its Secure, HttpOnly, SameSite=None `__Host-google_signin_nonce` cookie. It passes the nonce to GIS, then POSTs JSON `{ "credential": "<ID token>", "state": "<Portal state>" }` to the same endpoint. Tokens never belong in URLs or logs. Nonces are consumed once, including failed verification, and the cookie is deleted. This in-memory nonce store requires sticky routing between challenge and callback; restarts require a fresh challenge. Browsers blocking third-party cookies may require hosting login-view on the same site as Portal.

`/google/link` requires an existing, unexpired, verified Portal access-token cookie. The challenge is bound to that Portal UUID, and linking preserves its identity and permissions without issuing a replacement session. The user must explicitly visit login-view with `?link_google=1` after signing in to Portal. Email matches never link accounts automatically. Google-subject bindings determine subsequent sign-in and retain the stored Portal email. New registration is allowed only for Gmail or a verified Google Workspace hosted domain; other Google emails must link an existing account.

Apply the Portal binding migration and configure the Portal gateway audit actor before enabling the paired browser and gateway changes. Local tests use signed fixtures, an HTTP callback server and mocked identity/OAuth services; they are not evidence of a live Google login or deployed CORS/cookie behavior.
