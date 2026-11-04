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

The implementation must inspect all supported locations and aliases, not just the top-level URI query. Alias matching is case-insensitive; underscore and hyphen variants are normalized. HTML-escaped URI separators such as `&amp;` must be decoded for parsing so subsequent security parameters are not swallowed into a single key. The original raw URI must remain preserved for auditability.

## 4. Protocol-specific policy

### 4.1 VLESS

- A UUID is required.
- The configuration must explicitly use TLS or REALITY.
- A server name (SNI) alone is not proof that TLS is enabled.
- Values representing no TLS (including `none` or an empty TLS mode) do not satisfy this requirement.
- Disabled certificate verification is rejected.

REALITY must not be silently converted into ordinary TLS or vice versa.

**REALITY validation:** the required public key and short ID must be present in the appropriate parsed representation. Missing required REALITY parameters should be rejected by static validation rather than filled with guessed values. Accepted aliases include `pbk` / `public_key` / `public-key` and `sid` / `short_id` / `short-id`. HTML-escaped query separators must not cause these fields to be lost during parsing.

A fingerprint must not be invented or inserted automatically when it was absent from the source. Compatibility errors such as a missing uTLS fingerprint belong to the relevant validation/runtime stage unless the project explicitly adopts a stricter static requirement.

### 4.2 VMess

VMess payload encryption and VMess header authentication are different properties. Transport TLS provides a separate authenticated encrypted layer. This policy **does not mandate double encryption** when TLS certificate verification is effective.

**Modern VMess header authentication is required:** `alterId = 0` (accepted source aliases: `aid`, `alterId`, `alter_id`). Positive or malformed values are rejected. In the present implementation, a missing alterId is also rejected rather than silently replaced with zero. Before relaxing that rule, confirm the exact default applied by the pinned extended sing-box backend for every supported input format.

A UUID is required. The permitted payload ciphers depend on transport:

| Transport protection | VMess payload cipher | Decision |
|---|---|---|
| TLS enabled with certificate verification | `auto`, `aes-128-gcm`, `chacha20-poly1305` | PASS |
| TLS enabled with certificate verification | `none` | PASS: TLS protects the channel |
| TLS enabled | `zero`, unknown, missing, or legacy cipher | REJECT pending separate review |
| No TLS | `auto`, `aes-128-gcm`, `chacha20-poly1305` | PASS (VMess payload AEAD, without TLS transport) |
| No TLS | `none`, `zero`, unknown, missing, or legacy cipher | REJECT |

`auto` is a client/backend selection mode, not an independently specified cipher. Compatibility and the actual chosen cipher remain dependent on the pinned sing-box implementation.

TLS and VMess payload encryption must not be confused: for VMess the `security` field can describe payload cipher; transport protection is represented separately.

### 4.2.1 Encryption layers and trust boundaries (rationale, not an additional filter)

For HTTPS browsing through VMess, up to **three distinct cryptographic layers** may be involved:

1. **Destination HTTPS (client ↔ website):** the browser or application authenticates the destination website and encrypts its own HTTPS session end to end, including across the proxy server.
2. **VMess payload AEAD (client ↔ VMess server):** when `auto`, `aes-128-gcm`, or `chacha20-poly1305` is used, VMess encrypts and authenticates the tunneled payload independently of the destination protocol.
3. **Transport TLS (client ↔ VMess server):** when enabled, TLS authenticates the proxy endpoint (subject to certificate verification) and protects the entire VMess transport on that hop.

Layers 2 and 3 are both between client and proxy; layer 1 normally terminates at the **destination website**, not at the proxy. The proxy's TLS certificate is **not** the destination website's HTTPS certificate. HTTP websites and some non-browser traffic do not provide layer 1.

These layers may be nested, but do not imply that three layers are mandatory. In particular, **verified TLS to the proxy makes additional VMess payload encryption unnecessary as a baseline requirement for confidentiality and integrity on the client-to-proxy hop**. This does not prove that all other protocol properties are equivalent, nor does it extend the proxy's TLS protection past the proxy server.

### 4.2.2 Why `none` and `zero` without TLS remain rejected

The prevalence of HTTPS does not make a universal proxy tunnel safe when its own payload protection is disabled:

- HTTPS protects HTTPS application data, but not arbitrary HTTP, plaintext DNS, or other traffic lacking its own end-to-end encryption.
- The client-to-proxy hop has no independent confidentiality and integrity protection for arbitrary payloads when both transport TLS and VMess payload encryption are absent.
- Destination metadata and traffic characteristics may be exposed; actual visibility depends on the VMess framing, encrypted header, destination protocol, and network observer. Do **not** claim that the destination address in a modern protected VMess header is automatically readable.

`none` omits VMess payload encryption but may retain VMess framing; `zero` omits payload encryption and uses less framing/overhead. These are distinct modes; neither supplies equivalent AEAD protection for arbitrary payloads without transport TLS. VMess header authentication must be considered separately from payload encryption.

**Current decision:** without transport TLS, both `none` and `zero` remain **REJECT**, regardless of whether many end destinations use HTTPS.

### 4.2.3 DPI detectability is a separate threat dimension

Encryption strength, transport authentication, and DPI resistance are **not interchangeable**:

- Without TLS, a DPI observer can analyze VMess-specific external protocol behavior even if payload AEAD is enabled. Encryption alone does not make the traffic indistinguishable from ordinary HTTPS.
- With TLS, passive network observers cannot directly read the VMess cipher choice or payload inside properly established TLS. Additional VMess AEAD may nevertheless alter record sizes, framing, timing, and overhead, which can affect statistical fingerprints.
- Omitting extra VMess encryption is **not proven** to reduce detectability in every deployment. Conversely, requiring double encryption solely to improve DPI resistance is also unjustified.
- The transport TLS fingerprint, traffic shape, endpoint reputation, active probing, and network conditions may all matter. These are effectiveness/anti-censorship considerations, not proof that a cryptographic configuration is safe.

**Current decision — unchanged:** retain the VMess acceptance matrix in §4.2. In particular, verified TLS + `none` remains **PASS**, TLS + `zero` remains **REJECT pending a separate compatibility/security decision**, and no TLS + `none`/`zero` remains **REJECT**. The discussion of DPI and the possibility of safely using `zero` over verified TLS are documented here as rationale and future-review topics **only**. Do not change the implementation or test expectations without an explicit policy decision.

### 4.3 Shadowsocks

A permanent hard-coded allowlist would obstruct future supported AEAD methods. The policy therefore maintains an **explicit classification**, not a claim that the current list is complete forever.

- Known insecure or legacy methods (including CFB, CTR, RC4, stream-cipher and `none` variants) are rejected as `legacy_shadowsocks_cipher`.
- Currently reviewed AEAD methods pass:
  `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`.
- Unknown methods are rejected as `unknown_shadowsocks_cipher`, **not** labeled cryptographically weak. New methods can be added after confirming their security properties and compatibility with the pinned backend.

This is deliberately fail-closed for unreviewed algorithms without treating them as necessarily unsafe. A method passing static security still needs the later core compatibility check.

The protocol alias `shadowsocks` → `ss` is naming normalization, not a cryptographic change.

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
- Every supported insecure alias, including case and underscore/hyphen variants, with an explicit truthy value is rejected.\n- HTML-escaped `&amp;` query separators are decoded for parsing; the original URI is preserved.\n- Malformed boolean values for certificate-verification controls are rejected.
- Explicit false values are allowed by this rule.
- Malformed values for certificate-verification controls are rejected.
- Nested TLS and supported plugin representations are inspected.

### VLESS / REALITY
- Missing UUID is rejected.
- VLESS without TLS or REALITY is rejected.
- SNI without TLS does not satisfy the TLS requirement.
- REALITY without required public key or short ID is rejected.\n- REALITY public key and short ID following HTML-escaped query separators are parsed and validated.
- Missing fingerprint is not silently populated by security screening.
- Explicitly disabled certificate verification is rejected.

### VMess
- Missing UUID is rejected.
- Explicit `alterId=0` is accepted; missing, malformed, and nonzero values are rejected.
- Without TLS, `auto` and explicitly accepted AEAD ciphers are accepted.
- Without TLS, `none`, `zero`, legacy, unknown, or unspecified ciphers are rejected.
- With TLS, `none` is accepted because transport TLS protects the channel; `zero` remains rejected pending separate review.
- Tests distinguish payload encryption from transport TLS.

### Shadowsocks
- Each explicitly rejected legacy method is rejected.
- Each currently reviewed AEAD method is accepted, including supported AEAD-2022 methods.
- Unknown methods are rejected as unverified, not classified as weak; missing methods are rejected.
- Adding new reviewed methods does not require redesigning the policy.
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

1. **Shadowsocks future methods:** periodically review new supported AEAD methods and add them to the classified set; unknown methods remain unverified until then.
2. **REALITY required fields:** confirm the parser's canonical field names and all accepted source aliases for public key and short ID, then enforce their presence in security screening.
3. **Malformed certificate-verification values:** confirm every supported representation and implement fail-closed handling consistently.
4. **Unknown-protocol setting:** reconcile `reject_unknown_protocols` with the ingest allowlist and remove any misleading or unused configuration.
5. **VMess absent alterId:** confirm the effective default for extended sing-box parser mode before allowing missing `aid`; current policy requires explicit zero.
6. **VMess auto:** verify the effective cipher selection of the pinned backend as part of compatibility review.
7. **VMess `zero` with verified TLS:** assess protocol semantics, backend support, and DPI implications separately; the current rejection remains in force until an explicit decision.

These are policy/implementation closure items, not reasons to redesign the rest of the pipeline.

## 9. Change control

When changing a security rule:

1. Update this document in the same change.
2. Add or update focused unit tests.
3. Explain the security rationale and compatibility impact in the commit or pull request.
4. Run the security-policy test suite.
5. Run a complete laptop test pipeline and inspect both accepted and rejected security records.
6. Do not use the number of surviving proxies as the acceptance criterion for a security change.

A policy change must be explicit. Do not silently change previously agreed exceptions, especially the VMess AEAD-without-TLS exception or the TLS-with-none allowance.

---

## 10. Current policy summary

| Protocol / property | Current documented rule |
|---|---|
| VLESS | UUID + explicit TLS or REALITY; no disabled certificate verification |
| VMess | UUID + explicit alterId=0; without TLS require auto/AEAD; with verified TLS allow none, but not zero |
| Shadowsocks | Reject legacy; accept reviewed AEAD and AEAD-2022 methods; reject unknown as unverified pending review |
| Trojan | Password required; preserve TLS and certificate verification |
| Hysteria2 | Authentication required; preserve QUIC/TLS and certificate verification |
| TUIC | UUID + password; preserve QUIC/TLS and certificate verification |
| Certificate verification | Explicitly disabled or malformed security-control values are rejected |
| Unknown protocols | Rejected at ingest; defensive security check and config wiring must be reconciled |

**This document records the project's current decisions and explicitly labels unresolved items. It does not claim that every item is already implemented or tested.**
