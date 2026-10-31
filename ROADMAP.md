# Roadmap

Future work and architectural changes that are intentionally deferred until the current end-to-end pipeline is stable enough to refactor safely.

## Canonical pipeline refactor

The long-term pipeline should not use URI, Clash, Xray, or sing-box configuration syntax as the internal source of truth. All supported inputs should be normalized into one protocol-aware canonical model, and runtime tests should be executed from that model through sing-box-extended-light.

Target architecture:

```text
Sources
  ↓
Canonical ProxyConfig
  ↓
sing-box-extended-light JSON
  ↓
tests
  ↓
qualified ProxyConfig
  ├─ Clash/Mihomo subscription
  └─ URI subscription
```

### 1. Input formats

Keep support for multiple source formats, but distinguish the primary production path from compatibility inputs.

Current preferred production input:

- plain TXT containing share URIs, because the currently selected production sources provide direct URI lists and this avoids unnecessary Base64 or third-party format conversion.

Compatibility inputs to retain:

- Base64-wrapped URI subscriptions;
- Clash/Mihomo YAML;
- Xray/V2Ray JSON;
- sing-box JSON.

Do not make any external format the canonical internal representation. Input parsers should only decode their source dialect and map connection-relevant semantics into `ProxyConfig`.

When the same provider publishes several variants of the same subscription, prefer the most direct/original representation that preserves the most connection semantics. Do not assume that a generated Clash profile is richer than the provider's original URI feed: extended URI parameters can contain information that is lost by third-party format conversion.

### 2. Canonical `ProxyConfig`

Make `ProxyConfig` the single source of truth for connection semantics.

The canonical model must represent supported protocol semantics independently of source spelling or vendor format, including transports, TLS/Reality settings, authentication, packet encoding, protocol-specific extensions, and other fields required by sing-box-extended-light.

Known real-world extensions that need explicit semantic review/mapping include, among others:

- XHTTP and structured XHTTP options;
- `packetEncoding` / packet encoding aliases;
- Reality `spx` / spider-X related settings;
- `fm` fragmentation/mutation extensions;
- `cs` cipher-suite extensions;
- ECH-related fields;
- Shadowsocks structured plugin options;
- Hysteria2 port hopping (`mport` / server-port ranges);
- Hysteria2 upload/download bandwidth aliases;
- certificate pinning such as `pinSHA256`;
- transport-specific early-data / header / authority options.

Unknown connection-relevant fields must not be silently discarded. They should either be mapped explicitly or rejected/flagged as unsupported until their semantics are understood.

Display metadata, provenance, measurements, lifecycle state, and labels must remain outside canonical connection identity.

### 3. Runtime rendering

The mandatory semantic renderer is:

```text
Canonical ProxyConfig
        ↓
sing-box-extended-light outbound JSON
```

Runtime/core/network testing must use this renderer.

The sing-box backend should become a mostly mechanical translation of canonical fields. It should not independently reinterpret source aliases such as Clash `*-opts`, URI query aliases, or Xray-specific field names. Those aliases belong in ingest/canonicalization.

A proxy is considered runtime-supported when its canonical semantics can be rendered correctly for sing-box-extended-light and the resulting configuration passes the relevant tests.

### 4. Tests

The main semantic invariant becomes:

```text
source dialect
    ↓
Canonical ProxyConfig
    ↓
sing-box-extended-light JSON
```

without silent loss of connection-relevant semantics.

Add fixtures from real production subscriptions for extended URI parameters and structured Clash/Xray equivalents. Cross-format fixtures should prove that equivalent configurations normalize to the same canonical semantics and identity.

URI round-trip validation remains useful, but it is no longer the global definition of proxy support. It applies only to configurations that are intended to be published through the URI renderer.

### 5. Publication

Publish qualified canonical proxies through independent output renderers:

```text
qualified ProxyConfig
  ├─ Clash/Mihomo subscription
  └─ URI subscription
```

The Clash/Mihomo renderer should produce a structured subscription suitable for NetShift where the target semantics have a supported Clash/Mihomo representation.

The URI renderer should produce share links for configurations that have a lossless supported URI representation, including supported extended URI parameters understood by the target client/runtime.

A URI-render failure must not reject an otherwise valid proxy from the main pipeline. It only makes that proxy unavailable in the URI output unless/until a lossless URI mapping is implemented.

Likewise, output-format limitations must remain separate from runtime qualification. A proxy that works through canonical `ProxyConfig` → sing-box-extended-light must not be marked globally broken solely because one publication renderer cannot express it.

### 6. Output choice for NetShift

NetShift is the primary subscription consumer. Keep both Clash/Mihomo and URI publication paths until real compatibility tests establish which representation preserves more of the canonical semantics for the target NetShift + sing-box-extended-light stack.

Do not choose the primary publication format solely on theoretical format richness. Verify the actual NetShift parsing path for extended fields such as XHTTP, Reality extensions, packet encoding, fragmentation, port hopping, certificate pinning, and structured plugin options.

### 7. Migration strategy

Implement this as a staged refactor rather than a rewrite:

1. keep the existing parsers and tests working;
2. extend canonical `ProxyConfig` semantics for real production fields;
3. make the sing-box-extended-light renderer authoritative for runtime tests;
4. remove duplicated alias/source-format interpretation from the backend;
5. decouple publication success from pipeline qualification;
6. add Clash/Mihomo publication alongside URI publication;
7. retain compatibility input parsers but keep plain URI/TXT as the current preferred production ingest path.

The existing dedup, carryover, security, latency, throughput, exit-IP, GeoIP, reliability, diversity, history, and retention stages should remain downstream of the canonical model and should not depend on the original source format.
