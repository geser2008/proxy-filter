# Native JSON converter experiment (phase 3, initial slice)

Branch: `feature/protocol-native-parser`. **Not enabled in production.**

## API

```python
from proxyfilter.native_experiment import convert_uri_to_native

result = convert_uri_to_native(proxy)
outbound = result.outbound  # native JSON outbound, not a full sing-box config
dropped = result.dropped_fields  # (name, reason), no values or credentials
lossless_field_screen = result.no_unclassified_loss
```

The experimental entry point uses a *copy* of `ProxyConfig`. It never modifies
`params`, `original_raw`, identity, deduplication, SQLite, or rendering. It
does not alter the production `standard` and `extended` backend modes.

The mapper reuses the existing native outbound implementation. The field
registry is currently an **implementation inventory**, not a full standard.
Known unimplemented connection-relevant fields (e.g. `fm`, `spx`, certificate
pins) are rejected, conflicting aliases are rejected, and unclassified keys
are omitted with diagnostics. This cannot prove unknown extensions are harmless.
The caller must not interpret an unclassified-field omission as semantic
equivalence.

Additional guards refuse unknown transports instead of silently replacing
them with TCP, prevent losing transport-specific TCP fields, and prohibit
guessing REALITY uTLS fingerprint. Some protocol-specific gaps remain and
need fixtures and validation against the installed sing-box binary.

`no_unclassified_loss` is deliberately narrower than semantic equivalence:
even `True` **does not imply** that the resulting outbound connects or
matches the extended parser's behavior.

## Local verification

From the repository root on the laptop:

```bash
python3 -m unittest tests.test_native_experiment -v
python3 -m unittest discover -s tests -p 'test_backend*.py' -v
python3 tools/audit_uri_fields.py \
  --work ../data/work \
  --output /tmp/proxy-filter-uri-field-inventory.json
```

The inventory uses checkpoints from one run; verify they belong to the same
run before drawing comparisons. It exports field names/types/frequencies, not
URI values or credentials.

## Next gates

1. Review complete field inventory from `01-parsed` and `03-safe`, not just
   the 67 survivors. Build real but secret-free fixtures for each protocol.
2. Close the explicit mapper gaps (especially XHTTP `extra` encoding, transport
   headers, VMess aliases, HY2 pinning, and protocol-specific TLS semantics).
3. Add an **independent** A/B harness running identical URI profiles through
   extended parser vs experimental native JSON with identical probe conditions.
4. Record separately: check, network connectivity, latency, download, upload,
   exit IP, and both semantic differences and dropped fields.
5. No promotion to production before empirical evidence; no automatic fallback
   that would hide native mapper defects.

## Phase 4a: independent core-check A/B (implemented)

`tools/ab_core_check.py` compares **the identical** safe checkpoint URI
through (A) the extended `type=parser` outbound and (B) the experimental
native JSON outbound. Both use identical DNS, route and inbound settings.

From the repository root, after fetching the branch:

```bash
python3 -m unittest tests.test_native_experiment tests.test_ab_core_check -v
python3 tools/ab_core_check.py \
  --checkpoint ../data/work/03-safe.jsonl \
  --extended-bin /path/to/sing-box-extended \
  --native-bin /path/to/sing-box \
  --limit 100 \
  --output /tmp/proxyfilter-ab-core.jsonl
```

The `--extended-bin` **must actually support** `type=parser`; upstream
standard sing-box cannot validate that outbound. A single extended executable
may be passed for both modes when its native JSON support is being compared
against its URI parser. Use the same binary version where possible to isolate
interpretation differences.

Each JSONL record contains a SHA256 of the source URI, protocol, independent
A/B `pass/check_failed/timeout/binary_error` statuses, mapping status, and
dropped field **names/reasons**, with no raw credential values. The static
security gate runs again even though the input is `03-safe`, and the script
refuses other checkpoints to avoid accidentally probing rejected inputs.

The core-check stage is *offline*: it **does not** establish a connection,
measure latency, throughput or exit IP, and no `pass` implies semantic
equivalence. Core-check differences should guide fixtures before a later,
independently reported **network** A/B stage.

The experimental mapper now distinguishes VMess legacy `type` (TCP header
type) from `net` (transport), rejecting unsupported VMess HTTP header
variants rather than treating them as networks. For XHTTP URI `extra`, it
expects Base64URL(JSON) and decodes into a private copy for the extended
native mapper; plain JSON text is not accepted as a share-URI `extra`.
Even then, XHTTP remains version/build-specific and needs binary validation.

### Preflight and direct invocation

The A/B script accepts direct invocation (`python3 tools/ab_core_check.py`)
from the project root as well as `python3 -m tools.ab_core_check`.
Before reading the checkpoint, it calls `sing-box version` for **both**
configured binaries, validates the extended build marker and requires identical
version strings. The script prints both versions. Using the same extended
binary in both arguments is the recommended experiment, because it isolates
URI parsing from JSON mapping rather than comparing different core builds.

```bash
python3 tools/ab_core_check.py \
  --checkpoint ../data/work/03-safe.jsonl \
  --extended-bin "$(command -v sing-box)" \
  --native-bin "$(command -v sing-box)" \
  --limit 100 \
  --output /tmp/proxyfilter-ab-core.jsonl
```

If the preflight fails, no A/B records are produced. The version marker check
is a *sanity check*, not a substitute for testing actual `type=parser` support
with `sing-box check`. On the same build both parser and native outbounds are
validated independently against the same schema.

Run the dedicated regression tests:

```bash
python3 -m unittest tests.test_ab_core_check -v
```

The A/B checkpoint default is anchored to the repository layout:
`<project>/data/work/03-safe.jsonl`, with the Python package and tools under
`<project>/app/`. The default does not depend on the current working directory.
For a custom path, pass `--checkpoint`; nonexistent inputs fail before
creating or truncating the report file.

## Phase 4b: diagnostic A/B

The runner records stable conversion reason codes and categorized sing-box check
failures. It does not copy exception messages or raw sing-box output to the
JSONL report. Classification of core output is heuristic.

Run the complete checkpoint rather than the initial 100 records:

```bash
python3 -m unittest tests.test_native_experiment tests.test_ab_core_check -v
python3 tools/ab_core_check.py --limit 0 \
  --output /tmp/proxyfilter-ab-core-full.jsonl
```

The console summary now includes per-protocol outcomes and conversion reasons.
A full checkpoint core check is not a network connectivity benchmark.

## Phase 4c: field-level diagnostics (still experimental)

The complete earlier checkpoint contained 8,848 profiles: 2,345 native
conversion refusals, of which 1,136 were in the aggregate
`unsupported_connection_field` category. The new version reports the
**names only** of statically recognized unsupported fields:
`conversion_fields`, plus `conversion_fields` and
`by_protocol_conversion_field` counters in the printed summary.
`transport_fields_on_tcp` also reports which of the fixed
`host/path/headers/serviceName/service_name` fields caused the refusal.
No source values, endpoint names or raw exception messages are copied.

Because an arbitrary URI query *key* can itself contain private user text,
`dropped_fields[].name` now uses a fixed diagnostic allowlist.
An unrecognized name is emitted as `<other_field>` and its reason as
`unclassified`; the original input is left intact.

Use from `app/`:

```bash
git pull
python3 -m unittest tests.test_native_experiment tests.test_ab_core_check -v
python3 tools/ab_core_check.py --limit 0 \
  --output /tmp/proxyfilter-ab-core-detailed.jsonl
```

This run will expose which **registered unsupported keys** are prevalent
without needing to disclose proxy URIs. It will not automatically explain
`backend_mapping_error` or `other_check_failure`: categorization of
unknown mapper/core messages remains deliberately conservative. Do not
interpret a `pass` as a real network connection, or ignore source fields
merely because `sing-box check` accepts the generated JSON.

### Additional classification of reused mapper errors

The A/B runner also recognizes a limited set of literal error prefixes from
the existing `singbox_backend.py`: unsupported TCP header, unsupported V2Ray
transport, invalid boolean, invalid XHTTP JSON, unsupported XHTTP field,
invalid transport headers/multiplex, and unsupported network. These become
fixed `backend_*` diagnostic codes. Unknown messages remain
`backend_mapping_error`; the tool never copies the original message or
parameter value into the report.

This change does **not** alter URI parsing or the native outbound mapping.
The earlier full report remains valid as the *baseline*; updated failure
breakdowns require a new A/B run.

## Phase 4d: conservative field-loss gate and boolean diagnostics

On the observed full dataset, VMess had 80 `backend_invalid_boolean`
conversion refusals. The new A/B output may include the *field name* for
source-reviewed mapper messages of the form
`invalid boolean value for <known-field>:`. It never includes the
offending value. Messages without a known field remain classified only at
the error-code level.

Native conversion now rejects a bounded registry of unimplemented
connection-relevant URI keys (e.g. `peer` on Trojan,
`security` on Hysteria2, `type` on Shadowsocks) instead of treating them
as harmless unknown fields. The refusal code is
`unmapped_connection_field`; the original source is not changed.

This intentionally can **increase** the number of native mapper rejections.
Higher pass rates are not evidence of correctness when achieved by silently
losing configuration. Unsupported `pcs`, `spx`, `ech` and other
connection-defining fields remain rejected.

Run after fetching the updated branch:

```bash
python3 -m unittest tests.test_native_experiment tests.test_ab_core_check -v
python3 tools/ab_core_check.py --limit 0 \
  --output /tmp/proxyfilter-ab-core-phase4d.jsonl
```

Do not publish the source `03-safe.jsonl`; the JSONL report contains only
bounded diagnostic names and status codes.

### Certificate fingerprint semantic guard

The experiment rejects `hysteria2`/`hy2` and `tuic` profiles with an
explicit `fingerprint` certificate pin, including profiles also specifying
`fp` for uTLS. The reused backend previously rejected one combination but
could otherwise omit the pin. The refusal code is
`unsupported_certificate_fingerprint`. A successful `sing-box check`
does not prove that omitted certificate pins are harmless.

## Phase 4e: focused mismatch checks

Full phase 4d report: 8,848 profiles. The principal unresolved discrepancy is
320 extended-pass/native-check-failed profiles (309 VLESS, 10 VMess, 1 Trojan).
A full rerun is unnecessary to investigate this specific class.

The A/B runner now accepts an existing *sanitized* A/B JSONL file as
`--focus-report`. It selects **only** URI SHA256 hashes whose extended
check passed and whose native check failed, then matches those hashes against
the current `03-safe.jsonl`. No raw links or credentials are read from the
focus report. The source checkpoint must still be locally available.
If the source checkpoint has changed, selected records might not be found.

```bash
git pull
python3 -m unittest tests.test_native_experiment tests.test_ab_core_check -v
python3 tools/ab_core_check.py \
  --focus-report /tmp/proxyfilter-ab-core-phase4d.jsonl \
  --limit 0 \
  --output /tmp/proxyfilter-ab-core-focused.jsonl
```

The error classifier adds low-confidence `*_mentioned` categories (e.g.
`reality_mentioned`, `tls_mentioned`, `certificate_mentioned`) when
`sing-box check` fails but the earlier parser does not recognize its error.
These categories say **only that a keyword was present**, not that this
feature caused the failure. Raw stderr/stdout still never goes into JSONL.

The tool also reports `conversion_value_shape` for recognized invalid
boolean mapper values (e.g. `empty_string`, `nonempty_string`,
`number`), without disclosing the value. In the phase 4d report all
80 VMess `backend_invalid_boolean` cases referred to `insecure`;
changing empty/invalid values to `false` has NOT been implemented because
semantic equivalence with the extended parser has not been established.

## Phase 4f: outbound transport shape of failing native checks

Focused A/B report contained 320 stable extended-PASS/native-FAIL cases:
309 VLESS, 10 VMess, 1 Trojan. Of these, 291 VLESS errors were
`transport_mentioned`, which does **not** identify the actual failing
transport kind or specific field.

The focused runner now records `native_transport` (`none`, `ws`,
`grpc`, `http`, `httpupgrade`, `xhttp`, or `other`) and
`native_transport_fields`, a sorted set of field names restricted to
a static allowlist. Unsupported/unexpected names become `other`.
These are derived from the **generated native outbound**, not from
arbitrary user-supplied URI names or values. No header/path/server/secret
values are emitted. The console summary groups results and errors by
protocol and native transport type.

Run the existing focus report again after `git pull` and the unit tests:

```bash
python3 -m unittest tests.test_native_experiment tests.test_ab_core_check -v
python3 tools/ab_core_check.py \
  --focus-report /tmp/proxyfilter-ab-core-phase4d.jsonl \
  --limit 0 \
  --output /tmp/proxyfilter-ab-core-transport.jsonl
```

This is diagnostic instrumentation only. A transport keyword in core
stderr does not establish that the transport itself was invalid, and no
production code or mapper semantics changed.

## Phase 4g: isolate XHTTP native check failures safely

The focused transport report contains 320 A-pass/B-fail rows: 291 VLESS
XHTTP, 18 VLESS without transport, 10 VMess WS, 1 Trojan without transport.
The XHTTP failures span multiple field combinations, including 24 with
only `{"type":"xhttp"}`.

The extended fork publishes XHTTP native-JSON examples, so this report
does not prove that native XHTTP is unavailable. Diagnose the installed
binary's actual behavior first, with a **synthetic** smoke test:

```bash
python3 tools/ab_xhttp_smoke.py 2>&1 | tee /tmp/proxyfilter-xhttp-smoke.log
```

This script never reads `03-safe.jsonl` or real URIs. It generates four
static configurations (WS control, minimal XHTTP, XHTTP with path, XHTTP
with mode/path) using a dummy UUID and `example.org`, calls
`sing-box check` without starting a proxy or contacting the endpoint,
and prints the core's full diagnostic text. **Only the output of this
synthetic probe** is suitable for sharing unredacted; do not copy full
stderr from tests involving real proxy configs.

If WS control passes but minimal XHTTP fails, identify the specific core
error before changing the mapper. If all four pass, investigate the
generated XHTTP options and the A/B configuration differences instead.

### XHTTP padding decode failure isolated

A synthetic check on `sing-box 1.14.3-extended-2.7.3-lite` produced:
`x_padding_bytes cannot be disabled` with no `x_padding_bytes` key.
The fork's `option/v2ray_transport.go` enforces a positive range when
unmarshalling native JSON, while its `GetNormalizedXPaddingBytes()`
uses the range `100-1000` if the range is unset. The fork's example client
config also supplies `x_padding_bytes: "100-1000"`.

The synthetic smoke tool now checks three additional XHTTP cases with
explicit `x_padding_bytes: "100-1000"`. Do **not** insert a silent default
into the production mapper yet: compare actual check results, verify how the
extended URI parser handles absent/explicit padding, and later test real
network behavior to establish equivalent semantics.

```bash
git pull
python3 tools/ab_xhttp_smoke.py
```
