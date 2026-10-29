# OAuth callback and provider diagnostics

[Issue #191](https://github.com/networknt/light-spa-4j/issues/191) tracks the
logging review deferred from the cookie-sourced A28 changes.

Authorization code/state, complete TokenResponse results, GitHub authorization
codes and Portal social-user command payloads are no longer logged by the scoped
callers. Provider Status diagnostics retain only the HTTP status integer.
PortalClient records an exception class rather than its message/cause, and uses
the same safe class metadata in generic error Status objects. The token-exchange
failure response uses a fixed provider-failure argument rather than a raw provider
description. Authentication decisions, configured error codes/statuses, token
verification and cookie policy are unchanged.

Tests exercise the real local authorization callback at TRACE with distinct
code/state/refresh-token canaries. Portal provider failures carry canary/CRLF
exception messages and social-user command data; both returned statuses and log
messages/arguments/throwables are checked without contacting an external provider.
Existing cookie/session logging regressions remain in the selected reactor.

This is scoped caller-side redaction, not proof that every dependency, transport
or deployment log is safe. PortalClient's legacy command/query transport still
places encoded application data in a URL; protect access logs and review that
separate server/client protocol before exposing it to untrusted infrastructure.
Live identity providers, deployed logs and partner rescan are not qualified here.

Recorded selected-reactor validation: master reports 153 tests and 2.x reports 79,
with zero failures/errors and one existing skip per branch. The 2.x run explicitly
excludes two legacy Azure tests whose fixture configuration names Microsoft
endpoints. Reintroducing the callback code/state log makes the real local callback
canary test fail without changing its successful HTTP response.
