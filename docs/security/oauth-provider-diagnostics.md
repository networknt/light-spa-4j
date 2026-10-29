# OAuth callback and provider diagnostics

[Issue #191](https://github.com/networknt/light-spa-4j/issues/191) tracks the
logging review deferred from the cookie-sourced A28 changes.

Authorization code/state, complete TokenResponse results, GitHub authorization
codes and Portal social-user command payloads are no longer logged by the scoped
callers. Provider Status diagnostics retain only the HTTP status integer.
Stateless/Facebook token failures preserve the provider HTTP status but return
the configured ERR10014 generic response with a fixed argument, rather than the
provider's code/message/description. MSAL retains its configured ERR11648 response
and fixed safe argument. This intentionally redacts those error bodies; success,
verification decisions and cookie policy are unchanged.

Portal diagnostics use a sanitized throwable copy: fully qualified exception
names (including anonymous types), up to 32 stack frames per node, a bounded
cause/suppressed chain and validated SQLState/vendor metadata. Provider exception
messages are never copied. Cycle/size limits bound diagnostic traversal. Generic
Portal exception statuses use fixed text. Raw server-returned Portal Status
values remain part of that legacy API, but these callers do not log them wholesale.

The duplicate MSAL PortalClient was documentation-equivalent to the stateless-auth
implementation. MSAL now uses the class from its existing stateless-auth dependency;
no new runtime artifact is introduced. Deploy matching modules from the same build.
Tests in both modules exercise that shared implementation, including constructor
failures, anonymous types, nested SQL causes, suppressed messages and cycles.

## Regression scope

The callback refresh-token fixture now chooses its canary as the final value;
the test requires that value in the returned cookie before checking logs. Local
HTTPS probes cover the actual stateless and Facebook failure handlers, GitHub's
existing code-processing stub and MSAL token-exchange failure. Facebook/Portal
and legacy MSAL trust boundaries are substituted locally; no live provider is
contacted. Root appenders inspect messages, arguments, MDC and throwable chains.
Portal failure probes raise all existing loggers/root to TRACE. Callback probes
raise auth loggers to TRACE with root capture at WARN: XNIO raw wire TRACE can
include their legacy credential-bearing URLs and is a separate transport boundary.
This is not a repository/dependency-wide claim of secret-free TRACE output.

Logging-only negative controls retain HTTP behavior and require canary detection
when result logging, raw MSAL Status logging or raw provider error responses are
reintroduced. The corrected refresh-token control fails on the result-log mutation.

PortalClient's legacy command/query transport also places encoded application
data in a URL. Protect access logs and review that separate server/client protocol
before exposing it to untrusted infrastructure. Live identity providers, deployed
logs, full-repository qualification and partner rescan are not established here.

Recorded clean affected-reactor results: 159 tests on master and 85 on 2.x,
zero failures/errors and one existing skip each. The 2.x run explicitly excludes
two legacy Azure methods whose fixtures name Microsoft endpoints. These are
selected component results, not full-repository/live-provider qualification.
