# Security Policy

**Status:** working policy for the `security-hardening` branch  
**Scope:** static security screening of proxy configurations in `proxy-filter`  
**Purpose:** reject configurations that violate the project's security requirements before runtime testing. This document does not define proxy availability or performance criteria.

This document records decisions already made in the project and identifies items that still require an explicit decision. An implementation detail or a test passing is not, by itself, a policy decision.

## 1. Responsibilities and pipeline boundaries

The pipeline stages have separate responsibilities:

| Stage | Responsibility |
|---|---|
| Ingest / parse | Accept supported URI formats and parse source data without silently inventing missing values |
| Deduplication | Identify duplicate proxy configurations |
| Security | Reject configurations that violate the static security policy in this document |
| Core | Check whether the configured sing-box version can parse and initialize the configuration |
| Latency | Check reachability / response through the proxy |
| Download / upload | Check practical data-transfer functionality |
| Publish / history | Publish results and maintain historical reliability information |

A failure at a later stage is not evidence that a configuration failed the security policy. In particular, low latency-stage yield, HTTP 503/504 responses, timeouts, or a small final subscription are not reasons to weaken or broaden security rules.

Security screening must not attempt to maximize the number of surviving proxies.

## 2. General principles

1. **Fail closed for security-sensitive ambiguity.** Unknown or malformed values that affect a security decision must not be silently interpreted as safe.
2. **Do not invent configuration.** Do not add TLS, REALITY parameters, fingerprints, credentials, or other values that were absent from the source.
3. **Do not silently rewrite security semantics.** Normalization may standardize protocol aliases, but must not change the security properties of a proxy.
4. **Preserve source information.** Retain original parameters and rejection reasons in the working records so that decisions can be audited.
5. **Separate security from compatibility and availability.** A configuration may be secure but unsupported by the current core; it may also be supported and reachable without meeting this project's security profile.
6. **Be explicit about exceptions.** Any exception must be documented here and covered by tests.

## 3. TLS certificate verification

A configuration that explicitly disables certificate verification must be rejected.

The policy applies to all supported spellings and representations of the relevant setting, including (where applicable):

- `allowInsecure`
- `allow_insecure`
- `skip-cert-verify`
- `skip_cert_verify`
- `insecure`
- nested TLS options
- protocol-specific plugin options, including Shadowsocks plugin options

Interpretation:

- Explicit `true`, `1`, `yes`, or `on`: **REJECT**.
- Explicit `false`, `0`, `no`, or `off`: allowed by this rule.
- Missing value: does not by itself mean verification is disabled.
- Unrecognized or malformed value: **REJECT** when it is supplied for a certificate-verification control. Do not silently coerce it to false.

The implementation must inspect all supported locations and aliases, not just the top-level URI query.

## 4. Protocol-specific policy

### 4.1 VLESS

- A UUID is required.
- The configuration must explicitly use TLS or REALITY.
- A server name (SNI) alone is not proof that TLS is enabled.
- Values representing no TLS (including `none` or an empty TLS mode) do not satisfy this requirement.
- Disabled certificate verification is rejected.

REALITY must not be silently converted into ordinary TLS or vice versa.

**REALITY validation:** the required public key and short ID must be present in the appropriate parsed representation. Missing required REALITY parameters should be rejected by static validation rather than filled with guessed values. The exact accepted field aliases must match the formats supported by the parser and sing-box backend.

A fingerprint must not be invented or inserted automatically when it was absent from the source. Compatibility errors such as a missing uTLS fingerprint belong to the relevant validation/runtime stage unless the project explicitly adopts a stricter static requirement.

### 4.2 VMess

A UUID is required.

The project previously discussed and implemented a deliberate exception for VMess without transport TLS: it may pass the static security rule when its VMess payload-security value is one of the explicitly accepted AEAD values:

- `auto`
- `aes-128-gcm`
- `chacha20-poly1305`

This exception distinguishes VMess payload encryption from transport TLS. These are different security properties; passing this rule does not mean that the connection has TLS transport protection.

The following are not accepted as a basis for allowing VMess without TLS:

- `none`
- unspecified or empty payload-security values
- unknown values

**Policy status:** preserve the previously agreed AEAD exception unless and until the project explicitly decides to remove it. Do not silently change the rule to require TLS for every VMess configuration. Any future change must update this section and the corresponding tests together.

### 4.3 Shadowsocks

Known legacy / non-AEAD methods are rejected. The project has explicitly discussed rejecting methods including:

- `aes-128-cfb`
- `aes-256-cfb`
- `rc4-md5`

The current implementation has used a denylist of legacy methods. A denylist is not equivalent to a strict allowlist: an unrecognized method must not automatically be treated as secure.

**Decision still required:** finalize the exact allowlist of accepted Shadowsocks AEAD methods, based on the methods supported by the project's pinned sing-box version and the project's security requirements. Until that list is agreed and implemented, unknown or unrecognized methods must not be described as verified secure.

Do not add or rename cipher methods merely for convenience. Protocol aliases such as `shadowsocks` → `ss` are normalization, not a security decision.

### 4.4 Trojan

- A password is required.
- Trojan's TLS behavior must be preserved by parsing and backend conversion.
- Certificate verification must not be disabled.
- A missing or malformed required credential is rejected.

Do not infer that a configuration is secure merely because a password is present; the backend representation must retain the protocol's TLS requirements.

### 4.5 Hysteria2

- Authentication is required; supported password/auth aliases must be handled consistently.
- Hysteria2's QUIC/TLS transport semantics must be preserved.
- Certificate verification must not be disabled.
- Missing or malformed required authentication data is rejected.

The URI alias `hy2` may be normalized to `hysteria2`. This is a naming normalization only and must not change the configuration.

### 4.6 TUIC

- UUID and password are required.
- TUIC's QUIC/TLS transport semantics must be preserved.
- Certificate verification must not be disabled.
- Missing or malformed required credentials are rejected.

### 4.7 Unknown protocols

Unsupported URI schemes are rejected during ingest using the supported-scheme allowlist. The security stage may retain a defensive check, but there must be one clearly defined source of truth for supported protocols.

The configuration option `reject_unknown_protocols` must either be wired into the actual enforcement path or removed/documented so it does not imply behavior that is not implemented. Do not silently accept an unknown protocol.

## 5. Protocol aliases and normalization

The following aliases have been discussed and accepted as naming normalization:

- `shadowsocks` → `ss`
- `hy2` → `hysteria2`

Normalization must occur without dropping credentials, TLS settings, cipher settings, plugin parameters, or other security-relevant fields.

Normalization must not be used to make an otherwise invalid configuration pass security screening.

## 6. Security versus core compatibility

Security checks answer: **does this configuration meet the project's declared security requirements?**

Core checks answer: **can the pinned sing-box version parse and initialize this configuration?**

Examples:

- A secure configuration using an unsupported transport may pass the security stage and fail core.
- A configuration that sing-box can initialize may still be rejected by security.
- A missing optional compatibility parameter must not be fabricated by security screening.
- A runtime error must not be relabeled as a security failure without a specific policy violation.

Keep security rejection reasons distinct from parser, core, latency, download, and upload errors.

## 7. Required test coverage

Every normative rule in this document must have unit tests. At minimum, tests should cover:

### TLS verification
- Every supported insecure alias with an explicit truthy value is rejected.
- Explicit false values are allowed by this rule.
- Malformed values for certificate-verification controls are rejected.
- Nested TLS and supported plugin representations are inspected.

### VLESS / REALITY
- Missing UUID is rejected.
- VLESS without TLS or REALITY is rejected.
- SNI without TLS does not satisfy the TLS requirement.
- REALITY without required public key or short ID is rejected.
- Missing fingerprint is not silently populated by security screening.
- Explicitly disabled certificate verification is rejected.

### VMess
- Missing UUID is rejected.
- VMess without TLS using each previously accepted AEAD value follows the documented exception.
- VMess without TLS using `none`, empty, unspecified, or unknown security values is rejected.
- TLS-enabled VMess is evaluated according to the accepted payload-security policy.
- Tests explicitly document the distinction between payload AEAD and transport TLS.

### Shadowsocks
- Each explicitly rejected legacy method is rejected.
- Each method on the final allowlist is accepted.
- Unknown and missing methods do not pass as secure by default.
- Supported plugin options are inspected for disabled certificate verification.

### Trojan / Hysteria2 / TUIC
- Required credentials are enforced.
- TLS verification cannot be disabled through supported aliases.
- Normalization preserves all security-relevant parameters.

### Ingest and protocol handling
- Supported aliases normalize correctly.
- Unsupported schemes are rejected.
- The configured unknown-protocol behavior matches the actual enforcement path.

## 8. Open decisions

The following items must be resolved before declaring the policy fully finalized:

1. **Shadowsocks allowlist:** agree the exact accepted AEAD methods against the pinned sing-box version. Until then, do not claim that a denylist provides strict allowlist-level assurance.
2. **REALITY required fields:** confirm the parser's canonical field names and all accepted source aliases for public key and short ID, then enforce their presence in security screening.
3. **Malformed certificate-verification values:** confirm every supported representation and implement fail-closed handling consistently.
4. **Unknown-protocol setting:** reconcile `reject_unknown_protocols` with the ingest allowlist and remove any misleading or unused configuration.

These are policy/implementation closure items, not reasons to redesign the rest of the pipeline.

## 9. Change control

When changing a security rule:

1. Update this document in the same change.
2. Add or update focused unit tests.
3. Explain the security rationale and compatibility impact in the commit or pull request.
4. Run the security-policy test suite.
5. Run a complete laptop test pipeline and inspect both accepted and rejected security records.
6. Do not use the number of surviving proxies as the acceptance criterion for a security change.

A policy change must be explicit. Do not silently change previously agreed exceptions, especially the VMess AEAD exception.

---

## 10. Current policy summary

| Protocol / property | Current documented rule |
|---|---|
| VLESS | UUID + explicit TLS or REALITY; no disabled certificate verification |
| VMess | UUID; documented AEAD exception for VMess without TLS remains in force |
| Shadowsocks | Reject known legacy methods; exact strict allowlist remains to be finalized |
| Trojan | Password required; preserve TLS and certificate verification |
| Hysteria2 | Authentication required; preserve QUIC/TLS and certificate verification |
| TUIC | UUID + password; preserve QUIC/TLS and certificate verification |
| Certificate verification | Explicitly disabled or malformed security-control values are rejected |
| Unknown protocols | Rejected at ingest; defensive security check and config wiring must be reconciled |

**This document records the project's current decisions and explicitly labels unresolved items. It does not claim that every item is already implemented or tested.**
