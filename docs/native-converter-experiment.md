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
  --work data/work \
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
  --checkpoint data/work/03-safe.jsonl \
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
  --checkpoint data/work/03-safe.jsonl \
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
