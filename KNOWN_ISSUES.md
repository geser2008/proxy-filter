# WANTTO

Deferred improvements to revisit after the end-to-end pipeline is working reliably.

## Parser / validation

- Keep URI parsing syntax-focused and universal.
- Consider adding a separate cheap semantic-validation stage before TCP/core checks instead of expanding the parser into a protocol validator.
- Candidate checks include protocol-required fields, enum values, parameter combinations, ranges, and other semantic constraints that can be validated without guessing or repairing source data.
- Preserve the project rule: parse exactly what the declared format means; reject malformed/unsupported configurations explicitly; do not infer intended values.

## Proxy identity / dedup canonicalization

- Preserve the current global dedup architecture in `global-pipeline-carryover`: combine newly parsed proxies from all selected sources with `state/working.jsonl`, then deduplicate once before the common pipeline. New records intentionally precede carryover records so a current observation wins when `proxy_id` is identical.
- Replace the current mostly structural `proxy_id` canonicalization with protocol-aware semantic canonicalization so equivalent proxy configurations receive the same stable ID across URI, Clash, and sing-box inputs. The global dedup stage itself does not need redesign; the defect is in identity construction.
- Keep display/provenance/runtime fields out of identity: proxy `name`, Clash `name`, sing-box `tag`, VMess `ps`, source ID/name/format, original raw text, lifecycle/test state, measured `exit_ip`, latency, throughput, reliability, and other observations must not affect `proxy_id`.
- Continue normalizing protocol casing, server casing/whitespace, integer ports, and deterministic dictionary key ordering.
- Normalize protocol aliases before hashing, especially `hy2` -> `hysteria2`, including plain URI input where this alias is not currently normalized at ingest time.
- Normalize known parameter aliases to one canonical key per semantic field. Examples already treated as aliases by the backend include `sni` / `server_name` / `servername` / `server-name`, `uuid` / `id`, `security` / `scy` / `cipher`, `alter_id` / `alterId` / `aid`, `allowInsecure` / `allow_insecure` / `skip-cert-verify` / `insecure`, `fp` / `client-fingerprint` / `fingerprint`, `plugin_opts` / `plugin-opts`, and `password` / `auth` where protocol semantics make them equivalent.
- Normalize value types where the backend treats them equivalently, for example explicit boolean spellings and integer-like strings for fields that are semantically integers. Do not guess or repair invalid values; invalid values should remain distinguishable and be rejected by validation.
- Make canonicalization protocol-specific rather than globally rewriting arbitrary keys. A key alias valid for one protocol must not silently change another protocol's identity.
- Avoid recursively dropping every nested key named `name`, `tag`, or `ps`. Exclude display-only fields at the appropriate top-level ingest boundary so a future nested semantic field with one of those names cannot disappear from identity accidentally.
- Canonicalize list-valued parameters according to protocol semantics: preserve order where meaningful and sort only fields explicitly known to be order-insensitive.
- Preserve provenance merging with `merge_sources_from()` when duplicate IDs are collapsed so one globally tested proxy retains all source memberships.
- Preserve the separation between deduplication and infrastructure diversity: identical/equivalent proxy configuration belongs to `proxy_id` dedup; shared exit IP/subnet/ASN belongs to the diversity stage and must not affect identity.
- Add regression tests proving that syntactically different but semantically equivalent configurations collapse to one `proxy_id`, while configurations differing in connection-relevant semantics remain distinct.
- Include cross-format fixtures for equivalent URI/Clash/sing-box representations and cases covering alias spelling, boolean/integer representation, query parameter ordering, display names, and `hy2` versus `hysteria2`.
- Add carryover-specific tests showing that an equivalent new proxy and old `working.jsonl` proxy collapse before testing, while a semantically distinct proxy is retained even if server/exit infrastructure is shared.
- After changing identity semantics, define an explicit history/state migration or versioning strategy because existing database and `working.jsonl` records were keyed with the old SHA-256 identity payload. Do not silently reinterpret old `proxy_id` values without a documented transition path.

## Security semantics

- Unify TLS/insecure interpretation between `security.py` and the sing-box backend. Today static security and backend rendering maintain separate alias/boolean logic, so a configuration can pass security but later be interpreted differently by the backend.
- In particular, do not treat merely having a non-empty `tls` dict or `servername`/`server_name` as proof that TLS is enabled; use the same canonical protocol semantics as the backend.
- Cover all aliases consistently, including `insecure` in addition to `allowInsecure`, `allow_insecure`, `skip-cert-verify`, and `skip_cert_verify`.
- Add regression tests where security policy and backend rendering must agree on TLS enabled/disabled and certificate-verification state.

## Render / round-trip compatibility

- Make URI rendering protocol-aware for typed Clash/sing-box parameters. The current generic renderer only accepts query values that are strings or lists of strings, so a proxy can pass core/network tests but fail publication solely because a valid boolean, integer, or nested parameter cannot be rendered.
- Define explicit lossless mappings for supported protocols and reject only configurations that genuinely have no supported URI representation.
- Keep `validate_round_trip()` as a hard invariant, but make parser and renderer share the same canonical protocol model so valid typed input round-trips reliably.

## GeoIP validation

- Verify that a successful GeoIP provider response refers to the IP that was requested. A provider returning another IP must be treated as an invalid response and should trigger fallback.
- Decide what minimum fields make a GeoIP response complete enough to stop fallback. A nominally successful response with no useful country/ASN data currently suppresses fallback even though downstream diversity/labels may lose information.
- Keep provider failures informational unless policy explicitly requires GeoIP success; do not reject otherwise working proxies because of enrichment outages.

## Download/upload measurement consistency

- Keep successful download payload-size validation and extend equivalent validation to upload where practical: compare `size_upload` with the configured payload size before treating the result as a complete measurement.
- Clarify staged fallback semantics for generic download backends. Cloudflare splits one total payload across streams and CacheFly uses ranges, while an arbitrary fallback may accidentally download the full object in every stream. Do not expose these as equivalent aggregate tests unless the backend can enforce comparable total bytes.
- Keep fallback/retry behavior bounded and record enough metadata to distinguish provider errors from proxy transport failures.

## Publication safety

- Restrict output cleanup to the canonical subscription files instead of deleting every regular file in `output/`. The current `_clean_output_dir()` can remove unrelated files placed there by operators or future features.
- Publish `all.txt`, `stable.txt`, and `unstable.txt` as one coherent generation. Avoid a state where a crash after cleanup or between individual writes leaves a partially updated subscription set.
- Prefer staging all output files first and committing them together with atomic renames/swap semantics.

## History consistency

- Fix the contradiction between `proxy_observations` and `proxy_source_state` for retained proxies absent from a source. `proxy_observations.present=0` currently can still carry `availability_state=available/degraded/...` because `_observation_record()` ignores `present`, while `_update_state()` correctly forces source state to `absent`.
- For a source-specific observation, `present=0` should imply `availability_state=absent`; test results may still be preserved in their dedicated fields to show that a retained proxy was re-tested successfully.
- Add invariants/tests so `present`, `availability_state`, and source-state history cannot describe mutually contradictory source membership.

## Carryover state model

- Remove or clearly separate the two parallel state files `state/known-working.jsonl` and `state/working.jsonl`. They now have different semantics, but `load_known_working()` can silently fall back from the retention-aware file to the legacy snapshot.
- After migration is complete, stop treating `working.jsonl` as an implicit runtime fallback, or rename/re-scope it as an explicit last-run diagnostic snapshot.
- Keep retention lifecycle (`first_seen`, `last_seen`, `last_working`, `last_tested`, consecutive failures) authoritative in one state model only.

## Pipeline architecture / entry point

- Remove runtime monkey-patching of `proxyfilter.cli` from `proxy_filter.py`. The launcher currently replaces ingest, carryover loading, render policy, and publish behavior dynamically, so direct package CLI execution and launcher execution can have different semantics.
- Make these policies explicit dependencies/configuration of one pipeline implementation, or make `proxy_filter.py` the sole supported entry point and keep `cli.py` internal.
- Add end-to-end tests proving that the supported entry point exercises the same ingest, retained-state, render, publish, warning, and history policies every time.

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
