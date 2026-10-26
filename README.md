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

`.github/workflows/jackson3-source-build.yml` builds the prerequisite source stack in an isolated Maven repository, reuses independently qualified full-core test evidence, and runs the prerequisite and full consumer suites. It pins reviewed policy `f0d2100f972eec765b2b276e7ace38922394f0a6` and candidate `97b2359b92ed3e1d05cac04f2da8760aa954e49d`; yaml-rule/http-client are selected from that verified evidence. Other prerequisites resolve once to full SHAs. The workflow uploads `source-refs.json`, `source-commits.txt`, `core-qualification.json` and Surefire reports. Core registration and workflow-token acceptance are merged in light-4j #2825 and #2826.

The source ledger audits all NetworkNT releases and snapshots and reports private Jackson 2 boundaries. Merge this migration before the gateway distribution.

Concurrent renewal fixtures use dedicated request threads so blocking loopback calls cannot starve the Java HTTP client common pool. The full suite is also checked locally with `-DargLine=-Djava.util.concurrent.ForkJoinPool.common.parallelism=3`.

Consumer CI requires retained successful full-reactor evidence for the actual checked-out light-4j SHA and the same yaml-rule/http-client source commits. Core PR CI explicitly checks out the PR head, not its merge ref. Replay dispatches cannot qualify consumers. The attempt-specific evidence artifact records the actual checkout, prerequisite SHAs and test totals. A later pending, failed or cancelled run does not invalidate earlier valid evidence. All API pages and retained attempts are considered; missing or expired evidence blocks reuse. `core-qualification.json` records the accepted run and artifact.
