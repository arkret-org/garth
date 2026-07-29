# Regression Review

## 2026-07-29 — authorization lease test fixture drift blocked the Garth test target

- Surface: `sync_client::send_queue` authorization lease fixture.
- Regression: the shared SDK added the required `authorization_rule_id` field, but Garth's test
  fixture still initialized the previous wire shape, so the library test target no longer
  compiled.
- Detection: Sidecar completion-gate verification with `cargo test sidecar`.
- Resolution: bind the fixture to its existing `realm_admission` authorization rule.
- Prevention dimension: shared closed-wire model changes must compile all direct consumer test
  targets in the same verification round.
- Status: resolved.
