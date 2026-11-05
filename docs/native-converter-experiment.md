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
