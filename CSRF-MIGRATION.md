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
binding and requires trusted browser provenance: an exact trusted Origin, the
gateway's direct request origin, or `Sec-Fetch-Site: same-origin` when Origin is
absent. A present malformed, `null`, or untrusted Origin is never overridden by
Fetch Metadata. Same-site and cross-site metadata alone are insufficient. This
fallback does not apply to unsafe HTTP methods or WebSockets. Preserve Origin
and Fetch Metadata through proxies; forwarding headers cannot establish trust.

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
including cookie/header agreement. Signed expired tokens can be used for
cleanup; expiry relaxation does not authorize API access. A POST with trusted
browser provenance can also clear unusable sessions: orphan cookies, old
unsigned CSRF cookies, and values signed by a removed key. This path only deletes
owned cookies; it neither authenticates nor forwards any request. Untrusted
requests cannot use it. No-session logout remains an idempotent POST.

An explicit `logoutCsrfEnforced: false` retains the existing observation-only
migration escape hatch and counters. Such deployments do **not** enforce logout
CSRF protection. Set enforcement to true as part of the rollout.

Exchange/stateless renewal preserves a verified strong (32-byte) CSRF nonce.
Rotating it on every ordinary refresh would invalidate headers already prepared
by parallel requests or another tab. Legacy UUID CSRF claims are upgraded to a
fresh 32-byte nonce on renewal; the gateway sets the new cookie pair and returns
HTTP 401 with message `SESSION_REFRESHED` and `X-Session-Refreshed: true`, without
injecting Authorization or invoking the downstream handler. The original action
was not executed. Retry explicitly after rereading the CSRF cookie; do not add
automatic replay of unsafe operations.

When the access cookie has disappeared but a refresh cookie remains, trusted
browser requests can likewise bootstrap a fresh signed session and CSRF nonce.
The unverified old CSRF cookie is never copied into the new token. This recovery
returns the same non-forwarding 401, including for a POST; it does not execute
that POST. Failed refresh clears owned cookies before a 401 requiring sign-in.
Untrusted or WebSocket requests cannot trigger recovery and receive a CSRF 401.
They do not lose cookies as a side effect. A trusted POST logout always provides
a cleanup path.

Concurrent refresh results are isolated by refresh token and verified CSRF
context; refresh-only recovery has a separate cache context. New login issuance
and recovery always use a fresh 32-byte nonce. Strong session nonces stay stable
through ordinary renewal; legacy values no longer survive indefinitely.

## Client and rollout checks

1. Provision keys for direct `msal-auth`, configure exact WebSocket Origins, and
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
   Controller end to end. Handle `SESSION_REFRESHED` as an unexecuted request:
   offer an explicit retry after reading the new cookies. Sign in again if the
   refresh itself is invalid; trusted-browser logout can clear stale cookies.
4. Keep cookies Secure in production and check their domain/path scope. A future
   `__Host-` naming migration needs frontend reader changes and host-topology
   validation; it is not part of this format/transport change.

Run backend validation with `mvn test` (or `mvn verify`). Handler and local TLS
tests are component evidence, not deployed Portal/browser/proxy qualification.
