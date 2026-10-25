# light-spa-4j
Middleware handlers for Single Page Application

For direct Entra browser sessions, see the [MSAL authentication configuration and migration guide](msal-auth/README.md).

All three handlers require the [CSRF configuration and migration steps](CSRF-MIGRATION.md),
including direct-MSAL signing keys, WebSocket Origins, and enforced logout.

[Stack Overflow](https://stackoverflow.com/questions/tagged/light-4j) |
[Google Group](https://groups.google.com/forum/#!forum/light-4j) |
[Gitter Chat](https://gitter.im/networknt/light-spa-4j) |
[Subreddit](https://www.reddit.com/r/lightapi/) |
[Youtube Channel](https://www.youtube.com/channel/UCHCRMWJVXw8iB7zKxF55Byw) |
[Documentation](https://doc.networknt.com/style/light-spa-4j/) |
[Contribution Guide](https://doc.networknt.com/contribute/) |

See [Token trust migration](TOKEN-TRUST-MIGRATION.md) for the isolated signing and application policies required by stateless-auth and msal-exchange (follow-up to #173 / #182).

## Jackson 3 source line

Framework mapper calls and Google authentication parsing use Jackson 3.2.3 with private strict-duplicate detection. The 2.x branch preserves the previous Jackson 2 line. Build against the migrated light-4j source, including its shared mapper-policy module. Microsoft authentication SDK dependencies may retain private Jackson 2 internals; this migration does not claim to remove those SDK boundaries.

The source-build workflow records prerequisite SHAs, requires a successful full-core run for the exact light-4j SHA, installs its source, and runs the complete SPA reactor suite. It audits all NetworkNT releases and snapshots and reports private Jackson 2 boundaries. Merge light-4j #2821 before this companion migration, and merge this migration before the gateway distribution.

Concurrent renewal fixtures use dedicated request threads so blocking loopback calls cannot starve the Java HTTP client common pool. The full suite is also checked locally with `-DargLine=-Djava.util.concurrent.ForkJoinPool.common.parallelism=3`.
