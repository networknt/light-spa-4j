# SPA CSRF configuration and migration

The three handlers share CSRF transport and comparison rules through `spa-auth-common`.
They generate 32-byte `SecureRandom` nonces instead of UUIDs. `msal-auth` binds its
CSRF value to the exact Microsoft access token using HMAC-SHA-256. `msal-exchange`
and `stateless-auth` retain their application's signed JWT `csrf` claim as the
binding authority. Cookie names remain `csrf` and `accessToken`.

## Configure direct MSAL sessions

Enabled `msal-auth` requires `csrfSigningKeyId` and `csrfSigningKeys`, in addition
to its Microsoft token trust configuration. Missing or invalid keys fail
configuration loading, including reloads. Invalid snapshots remain rejected
until corrected configuration is loaded; there is no unsigned fallback.

Generate each signing secret with a cryptographic generator. For example, write
a new key ring to a protected local provisioning file without printing it:

```sh
umask 077
python3 -c 'import secrets; print("k202610=" + secrets.token_urlsafe(32))' > csrf-keyring.secret
```

Provision the file contents through the deployment's secret management and
light-4j encrypted/externalized configuration mechanism. Do not commit the file
or use the public test fixture keys. The unpadded Base64URL key must decode to
at least 32 random bytes. The key identifier accepts 1–32 letters, digits,
underscores, or hyphens. Supply these externalized settings to the shipped
`msal-auth.yml` template:

```yaml
msal-auth.csrfSigningKeyId: k202610
# Secret value, shown structurally only; replace through secret configuration:
msal-auth.csrfSigningKeys: "k202610=<unpadded-Base64URL-secret>"
msal-auth.logoutCsrfEnforced: true
msal-auth.websocketAllowedOrigins: "https://portal.example.com"
```

Share the key ring across every replica serving these sessions. The wire value
is `v1.<key-id>.<nonce>.<mac>`. The MAC authenticates a fixed domain label, the
version/id/nonce prefix, and SHA-256 of the exact access token, using delimited
fields. The CSRF value contains no access-token claims. It is still a credential:
never log it. Module registration redacts the signing key ring.

For rotation, distribute `old=<old-secret>,new=<new-secret>` to all replicas
while `csrfSigningKeyId` is still `old`; then switch the active identifier to
`new`. Remove the old key after the chosen overlap window (normally at least
the maximum session/token lifetime, unless deliberately forcing re-login).
Mixed active keys work while every replica has both verification keys. Key
removal immediately invalidates sessions signed with that key. Replacing an
access token requires reissuing its CSRF value. Logins reusing the exact same
access token share this binding boundary.

## HTTP and WebSockets

Cookie-authenticated API requests normally send the opaque CSRF cookie value
in `X-CSRF-TOKEN`. Such requests containing a `csrf` query parameter are rejected
with HTTP 401 / `ERR10039`, even when a valid header is also present. Query data
on anonymous routes, login/callback dispatch, and OPTIONS preflight are not
globally intercepted. OAuth's separate `state` parameter remains supported.
Removing acceptance does not erase a URL already logged by an upstream proxy.
Remove query credentials from clients and review proxy/access logging.

Native read-only browser GET/HEAD requests (EventSource/SSE, images, download
links, and same-origin `window.open`) can use the CSRF cookie without a custom
header. The handler still verifies that cookie against the signed session
binding and requires trusted browser provenance: an exact configured HTTP browser
Origin, the gateway's direct request origin, or browser-generated
`Sec-Fetch-Site: same-origin`. The metadata describes the public request even when
a proxy terminates TLS or rewrites Host; it can establish same-origin provenance
with a well-formed HTTPS Origin even when the gateway sees HTTP. A present
malformed or `null` Origin is never accepted. Same-site and cross-site metadata
alone are insufficient. This fallback does not apply to unsafe HTTP methods or
WebSockets. Preserve the browser's Origin and Fetch Metadata through proxies;
forwarding headers cannot establish trust.

For clients without Fetch Metadata, or a separately hosted trusted UI, configure
the public browser origin explicitly, independently of WebSocket enablement:

```yaml
statelessAuth.browserAllowedOrigins: "https://portal.example.com"
msal-exchange.browserAllowedOrigins: "https://portal.example.com"
msal-auth.browserAllowedOrigins: "https://portal.example.com"
```

Do not infer public scheme/host from untrusted `Forwarded` or `X-Forwarded-*`
headers. Existing `websocketAllowedOrigins` entries remain trusted HTTP browser
Origins for compatibility, but `browserAllowedOrigins` does not enable WebSockets.

Browser WebSockets may send `csrf.<value>` in `Sec-WebSocket-Protocol`. Each
client must also offer a supported noncredential application protocol (for
example, `['chat', 'csrf.' + csrfValue]` when its server supports and negotiates
`chat`). The downstream server must select that application protocol. Offering
only `csrf.<value>` is rejected: browsers require a selected protocol, and
selecting the CSRF credential would expose it in the handshake response.
Each handler needs its exact allowed browser Origin configured:

```yaml
statelessAuth.websocketAllowedOrigins: "https://portal.example.com"
msal-exchange.websocketAllowedOrigins: "https://portal.example.com"
msal-auth.websocketAllowedOrigins: "https://portal.example.com"
```

Set only the handlers used by the deployment. Comma-separated origins are
supported; native lists also work in direct configuration maps. Use origins
such as `https://portal.example.com:8443`, without paths, trailing slashes,
wildcards, credentials, queries, or fragments. An empty list disables
cookie-authenticated WebSockets. Absent, `null`, malformed, or unlisted request
Origins are rejected, even when a CSRF header is supplied. Origin comparison
normalizes scheme/host case and omits explicit default ports (80/443).
Forwarding headers and Host are not used to construct the WebSocket allowlist.
A blank CSRF header can fall back to the WebSocket subprotocol; conflicting
nonblank values are rejected.

The gateway requires GET, a valid 16-byte WebSocket key, and version 13. These
end-to-end handshake headers can survive a proxy stripping hop-by-hop headers;
an explicitly supplied Upgrade header must be `websocket`. Direct HTTP/2
extended-CONNECT WebSocket termination is not implemented by this policy.
Duplicate CSRF subprotocols, duplicate credential headers, conflicting transports,
and oversized values fail closed. The handler removes CSRF subprotocol entries
before invoking downstream handlers so they cannot be selected or echoed as the
application protocol; other application protocols are preserved.

## Logout and renewal

`logoutCsrfEnforced` defaults to `true` in all three handlers and templates.
The usual logout path checks the access-token cookie and its bound CSRF value,
including cookie/header agreement. A usable cookie pair always requires that
proof, even from a trusted browser Origin. Missing or wrong **request** CSRF does
not make the cookie pair unusable: enforcement and would-reject counters still
apply. Signed expired tokens can be used for cleanup; expiry relaxation does not
authorize API access.

Only independently unusable cookie state can use trusted-browser cleanup:
missing/malformed access cookies, an absent/invalid cookie binding, old unsigned
CSRF cookies, or values signed by a removed key. This POST path only deletes owned
cookies; it neither authenticates nor forwards a request. An indeterminate JWT
key lookup is not proof of unusability and does not trigger cleanup. Untrusted
requests cannot use this fallback. No-session logout remains an idempotent POST.

An explicit `logoutCsrfEnforced: false` retains the existing observation-only
migration escape hatch and counters. Such deployments do **not** enforce logout
CSRF protection. Set enforcement to true as part of the rollout.

Exchange/stateless renewal preserves a verified strong (32-byte) CSRF nonce.
Rotating it on every ordinary refresh would invalidate headers already prepared
by parallel requests or another tab. Legacy UUID CSRF claims are upgraded to a
fresh 32-byte nonce on renewal; the gateway sets the new cookie pair and returns
HTTP **409** with code `SPA_SESSION_REFRESHED`, message `SESSION_REFRESHED`, and
`X-Session-Refreshed: true`, without
injecting Authorization or invoking the downstream handler. The original action
was not executed. Retry explicitly after rereading the CSRF cookie; do not add
automatic replay of unsafe operations.

When the access cookie has disappeared but a refresh cookie remains, trusted
browser requests can likewise bootstrap a fresh signed session and CSRF nonce.
The unverified old CSRF cookie is never copied into the new token. This recovery
returns the same non-forwarding 409, including for a POST; it does not execute
that POST. This outcome is distinct from both authentication failure and an
outage, so clients must not redirect to login for it. Existing clients may show an
ordinary recoverable error until explicit-retry UI handling is added; this change
does not claim transparent replay of the original action.

Timeouts (including a single-flight waiter's five-second deadline), network errors,
temporary token-server errors, and unknown outcomes preserve all cookies. They
return HTTP **503**, code `SPA_SESSION_TEMPORARY_FAILURE`, and `Retry-After: 1`,
without downstream execution. A late waiter cannot erase an owner's successful
session rotation. The owner is not canceled when a waiter times out. For proactive renewal, a temporary failure instead allows the original
request if its already verified access token is still unexpired after the attempt.
No cookies change in this fallback. If the token expires during the attempt, the
request receives the same non-forwarding 503; expired credentials are never forwarded.

Only an explicit terminal refresh-token result clears owned cookies and returns
a sign-in-required 401. Supported light-oauth signals are a returned Status with HTTP status
404 and code `ERR12029` (`REFRESH_TOKEN_NOT_FOUND`), and Rust light-oauth's exact
plain-text `Refresh token not found` response (HTTP 400 at the provider). The OAuth
helper discards non-JSON transport status and wraps this body as `ERR10052`; only
that exact wrapped description is terminal, never `ERR10052` generally. Generic
401s such as `ERR10053` from the OAuth client are **not** terminal: that client uses
401 for network errors too. Unrecognized provider error shapes remain temporary
rather than destroying a session.

Untrusted or WebSocket requests cannot trigger recovery and receive a CSRF 401.
They do not lose cookies as a side effect. An unusable partial session can still
be cleared by trusted POST logout.

Concurrent refresh results are isolated by refresh token and verified CSRF
context; refresh-only recovery has a separate cache context. New login issuance
and recovery always use a fresh 32-byte nonce. Strong session nonces stay stable
through ordinary renewal; legacy values no longer survive indefinitely.

## Client and rollout checks

1. Provision keys for direct `msal-auth`, configure HTTP browser Origins for TLS
   proxies/clients without Fetch Metadata and exact WebSocket Origins, and
   enable logout enforcement before deploying the new handlers. Deploy the new
   transitive `spa-auth-common` artifact with the handler jars.
2. Existing unsigned direct-MSAL CSRF cookies require re-login. Plan a coordinated
   cutover; old handlers cannot verify the new signed CSRF format securely.
3. Coordinate a Portal WebSocket client/backend update before rollout. The
   inspected Chat and Controller clients offer only `csrf.<value>`; they must
   additionally offer a protocol their downstream endpoint supports and selects.
   Login/exchange and HTTP clients can keep reading the opaque `csrf` cookie and
   sending `X-CSRF-TOKEN`; no login rewrite is required. Query-based clients must
   change. Verify login/exchange, HTTP, POST logout, renewal/expiry, Chat, and
   Controller end to end. Handle 409 / `SPA_SESSION_REFRESHED` as an unexecuted
   request: offer an explicit retry after reading the new cookies. Preserve the
   session and offer a later retry for 503 / `SPA_SESSION_TEMPORARY_FAILURE`.
   Sign in again only for a terminal authentication failure; trusted-browser
   logout can clear unusable stale cookies.
4. Keep cookies Secure in production and check their domain/path scope. A future
   `__Host-` naming migration needs frontend reader changes and host-topology
   validation; it is not part of this format/transport change.

Run backend validation with `mvn test` (or `mvn verify`). Handler and local TLS
tests are component evidence, not deployed Portal/browser/proxy qualification.

For logout with an unpublished JWT key ID, the gateway confirms that the key is
absent from a successfully fetched and parsed JWKS before treating the session as
unusable. Trusted-browser cleanup can then clear it. Failed or malformed JWKS
lookups remain uncertain and return 503 with cookies preserved.
