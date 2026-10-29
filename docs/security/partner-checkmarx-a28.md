# Checkmarx A28: SPA session-token logging

[Issue #188](https://github.com/networknt/light-spa-4j/issues/188) tracks Excel
rows 117–119. The original assessment was accurate for its reviewed master
revision, not a statement that all branches had the same mitigation.

## Branch re-evaluation

- Master af06c19738a6f898201ee9f71998bfa75d9293e8 already removed the reported
  cookie-JWT and CSRF diagnostics. It verifies tokens with the configured trust
  objects and uses fixed rejection descriptions. This PR adds regression tests
  and documentation only; no production behavior is changed on master.
- 2.x b5fe2e8664267451bfb2c2e6fbe7327fd95af674 still logged raw JWTs and submitted/
  token CSRF values in both handlers. Its CSRF mismatch status also included those
  values, allowing the shared status logger to repeat them. The query-CSRF fallback
  accepts decoded control-character input into that diagnostic. The same canary
  probes fail against the original 2.x source.

The 2.x source fix removes the direct JWT/CSRF logs and uses fixed CSRF mismatch
messages. Invalid/expired cookie tokens now receive a fixed 401 rejection rather
than escaping as raw verifier exceptions to the container. Key-resolution
VerificationException failures retain the server-error outcome but are rethrown
with a fixed message and no sensitive cause. Microsoft-token rejection and invalid
issued-token handling also omit raw exception messages/throwables. CSRF mismatch
still returns 401 with ERR10039; token rejection uses ERR10000.

The change does not backport master's larger trust/CSRF redesign: existing
verifiers, token policy, token/header placement, cookie contents/names and legacy
CSRF transports remain branch-specific. This is scoped logging remediation.

## Local verification

MsalSessionLoggingTest and StatelessSessionLoggingTest run the real handlers over
loopback HTTP with ephemeral RSA signing keys and administrator-selected local
verification keys. The legacy branch uses its actual JwtVerifier with local key
resolution; the current branch uses its actual JwtTrust with a local resolver.
No external OAuth/JWKS or Microsoft endpoint is contacted by these probes.

The probes cover valid sessions, submitted-CSRF mismatch, decoded query CR/LF,
signed claims containing control characters, malformed/tampered cookie tokens,
malformed Microsoft tokens and rejected issued tokens. Two additional 2.x cases
confirm key-resolution server errors are redacted without changing that outcome.
Checks inspect log messages, argument values, MDC, throwable chains, response
bodies and exceptions escaping to the container, rather than relying solely on
the configured logging backend. Positive controls require a successful signed
session. Negative controls restore the original 2.x handlers or reintroduce the
removed JWT log on master.

Fixtures use dynamic loopback ports and no live accounts. JUnit isolation and
auto-closed state restoration protect logger levels, verifier/configuration
fields, servers and HTTP clients. A module-local test setup is used because 2.x
does not contain master's shared SPA trust/CSRF module.

Recorded focused validation passed 13 probes on master and 15 on 2.x, with zero
failures/errors/skips. Restoring the original 2.x implementation failed all 15
probes (seven stateless and eight MSAL); restoring the JWT log on master failed
both handlers' positive-session probes.

The affected-module/dependency reactor reported 151 tests on master and 67 on
2.x, each with zero failures/errors and one existing skip. The 2.x run explicitly
excluded the two legacy testAzureMsal methods, whose fixture configuration names
Microsoft endpoints. These are selected reactor results, not a full-repository or
live identity-provider qualification.

Focused command:

```sh
mvn -o -pl msal-exchange -am clean test \
  -Dtest=MsalSessionLoggingTest,StatelessSessionLoggingTest \
  -Dsurefire.failIfNoSpecifiedTests=false
```

The legacy tests use light-4j 2.x prerequisites built locally from merged
05a86a5d9510f704168d58f3817d9a2514ae178c. Their dedicated security-a28 fixture
initializes nested JWT settings and disables key bootstrap/JWT caching so all
verification keys remain local to the test.

## Remaining boundaries

These source/logging checks are not a partner deployment rescan or live identity
provider qualification. A signed token is still a bearer credential and should
not be printed merely because its signature is valid. Actual forging requires a
transport accepting the control characters; the decoded-query probe establishes
that path for the old 2.x diagnostics, not all possible server/proxy setups.

Other callback path, authorization-code/state, scope and token-result logging
remains outside these three cookie-sourced findings and deserves a separate
review. This PR does not assert that every log in these handlers or framework
providers is safe. Verify deployed artifacts and logging configuration before
closing the partner findings.
