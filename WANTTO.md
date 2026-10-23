# WANTTO

Deferred improvements to revisit after the end-to-end pipeline is working reliably.

## Parser / validation

- Keep URI parsing syntax-focused and universal.
- Consider adding a separate cheap semantic-validation stage before TCP/core checks instead of expanding the parser into a protocol validator.
- Candidate checks include protocol-required fields, enum values, parameter combinations, ranges, and other semantic constraints that can be validated without guessing or repairing source data.
- Preserve the project rule: parse exactly what the declared format means; reject malformed/unsupported configurations explicitly; do not infer intended values.

## CLI / configuration error handling

- Add explicit fail-fast validation for launcher arguments and configuration before any source download or pipeline stage starts.
- Report missing `config.yaml` and `sources.yaml` files with clear paths and actionable error messages instead of raw tracebacks.
- Validate that the loaded YAML documents are mappings of the expected shape and reject malformed YAML/config structures explicitly.
- Validate required configuration sections and required fields before execution; report the exact missing or invalid key.
- Validate `sources.yaml` entries before processing: every source should have a non-empty unique `id`, a usable `url`, and any other required source metadata.
- Reject duplicate source IDs explicitly rather than silently selecting or overwriting one entry.
- When `--source <id>` is supplied and no source with that ID exists, terminate immediately with a clear message that includes the requested ID and, where useful, the available source IDs.
- Treat an empty configured source list as a configuration error for normal pipeline runs rather than completing successfully with zero work.
- Validate stage-related arguments (`--until`, `--resume-from`) and resume-file availability before starting work; report incompatible ranges or missing stage artifacts explicitly.
- Validate filesystem paths needed for runtime/output where practical, including permission failures, and distinguish "not found", "not readable", and "not writable" errors.
- Keep user-facing CLI errors concise and deterministic: no Python traceback for expected configuration/user-input mistakes; reserve tracebacks or detailed diagnostics for unexpected internal failures/debug mode.
- Add unit tests for each expected failure mode so error handling remains stable as CLI defaults and config layout evolve.

## Security policy

- Revisit whether VMess without TLS should be rejected by policy or retained with an explicit security warning/risk classification.
- Keep this decision protocol- and configuration-driven; do not use feed-specific exceptions or heuristic repairs.
- Add generic DNS-leak checks so accepted proxies can be verified not to expose resolver traffic outside the intended proxy path.
- Add generic IPv6/direct-route leak checks so a proxy cannot pass application tests while some traffic still escapes through the host's direct network path.
- Keep reputation, ASN, hosting-provider, and geography data informational by default; avoid hard rejection based only on reputation metadata because of likely false positives.

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

