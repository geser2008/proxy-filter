# WANTTO

Deferred improvements to revisit after the end-to-end pipeline is working reliably.

## Parser / validation

- Keep URI parsing syntax-focused and universal.
- Consider adding a separate cheap semantic-validation stage before TCP/core checks instead of expanding the parser into a protocol validator.
- Candidate checks include protocol-required fields, enum values, parameter combinations, ranges, and other semantic constraints that can be validated without guessing or repairing source data.
- Preserve the project rule: parse exactly what the declared format means; reject malformed/unsupported configurations explicitly; do not infer intended values.

## Speed-test validation

- Validate successful speed-test responses against the expected payload size, not only HTTP status and non-zero transferred bytes.
- Treat implausibly short HTTP 200 responses as invalid measurements rather than extremely low real throughput. Example observed: a nominal 100 MB CacheFly object returned only 25 bytes with HTTP 200 through some proxies.
- Make the expected size or minimum acceptable fraction configurable/generic rather than hard-coding behavior for one provider.
- Revisit fallback object sizing so primary and fallback downloads are comparable and do not transfer substantially more data than necessary.
- Prefer a fallback object near the primary test size (currently about 50 MB) when a reliable fixed-size endpoint is available.

## Upload fallback endpoint

- Keep the existing bounded retries: one retry for incomplete `HTTP 100 Continue` uploads with `Expect` disabled, and one retry for zero-byte transport failures before any HTTP response.
- Do not retry upload threshold failures; they produced a valid measurement.
- Add a second reliable upload endpoint when one is identified, so repeated EOF/HTTP infrastructure failures can be distinguished from proxy failures without guessing.
- Keep retries bounded and explicit so unstable proxies are not repeatedly promoted through the pipeline.

