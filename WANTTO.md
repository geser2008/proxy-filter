# WANTTO

Deferred improvements to revisit after the end-to-end pipeline is working reliably.

## Parser / validation

- Keep URI parsing syntax-focused and universal.
- Consider adding a separate cheap semantic-validation stage before TCP/core checks instead of expanding the parser into a protocol validator.
- Candidate checks include protocol-required fields, enum values, parameter combinations, ranges, and other semantic constraints that can be validated without guessing or repairing source data.
- Preserve the project rule: parse exactly what the declared format means; reject malformed/unsupported configurations explicitly; do not infer intended values.

## Latency 503 retry

- Retry latency failures that return `clash_api_http_503` once before final rejection.
- Prefer retrying the affected proxy individually or in a very small batch so a transient batch/runtime failure does not discard a working proxy.
- Do not retry ordinary `504 Timeout` results by default; those already consumed the configured timeout.
- Do not retry latency-threshold failures; they produced a valid measurement.
- Motivation: a proxy that failed with 503 in the batch test later succeeded in single-proxy debug mode, so at least some 503 failures are transient.

