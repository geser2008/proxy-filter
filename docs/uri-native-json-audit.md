# URI → native sing-box JSON: compatibility audit

Status: **phase 1 / code audit**, 2026-11-05. Branch: `feature/protocol-native-parser`.

## Scope and evidence

This is a source-code audit, **not a claim that every parameter is supported by sing-box 1.14.3** or that native JSON and the extended URI parser are network-equivalent. The runtime documentation/schema and real input distributions must still be checked against the installed binary. No production conversion, identity or history logic is changed by this document.

Source files inspected:

- `proxyfilter/ingest.py` — production accepts plain TXT / base64(TXT) of share links; `SUPPORTED_SCHEMES` and `parse_uri()`.
- `proxyfilter/model.py` — `ProxyConfig.params`, conservative `identity_payload()`, and `original_raw`.
- `proxyfilter/engine.py` — base native JSON outbound mapper.
- `proxyfilter/singbox_backend.py` — additional mappings, explicit unsupported cases.
- `proxyfilter/singbox_modes.py` — production extended/native dispatch.
- `proxyfilter/singbox_auto.py` — auto-detects extended vs standard.
- `proxyfilter/render.py` — source-field allowlists and round-trip validation.
- `proxyfilter/security.py` — security gate.

## Current pipeline

```text
plain or base64 TXT
       |
       v
  ingest.parse_uri
  - query values retained
  - VMess base64(JSON) decoded
  - SS SIP002/legacy variants decoded
       |
       v
 ProxyConfig {protocol,server,port,params,original_raw}
       |
       +--- sing-box-extended -> {"type":"parser","link":original_raw,
       |                           "tag":"proxy-out","domain_resolver":"dns-direct"}
       |
       +--- standard sing-box -> engine.py + singbox_backend.py JSON mapper
       |                         + unknown-field passthrough in singbox_modes.py
       |
       +--- render -> per-protocol allowable-field validation
                      -> URI generation -> semantic round-trip
```

**Important:** the `standard` backend is **not** a strict known-fields-only mapper today. `singbox_modes.py` intentionally passes unconsumed URI fields as top-level JSON keys, leaving validation to `sing-box check`. This conflicts with the proposed experimental policy of *dropping unknown fields with diagnostics*. The new policy must be implemented as a distinct, opt-in mode.

## Protocol field matrix (code-verified)

"Native mapping" below means mapping code exists; it does not guarantee `sing-box check` or network success.

| URI protocol | URI envelope and credentials | Current native JSON target | TLS / transport | Main known gaps / risks |
|---|---|---|---|---|
| `vless` | `vless://UUID@host:port?...#name`; `uuid`, `flow`, `packetEncoding` | `type=vless`, `uuid`, `flow`, `packet_encoding` | Generic TLS, REALITY `pbk/sid`, uTLS `fp`; TCP, WS, gRPC, HTTP/H2, HTTPUpgrade, XHTTP | `fm/final_mask` unsupported; `spx/spider_x`, ECH, peer-cert pin unsupported; KCP/QUIC/domain socket/splitHTTP unsupported; REALITY needs explicit uTLS semantics checked |
| `vmess` | Base64 JSON with `add,port,id,aid,scy,net,path,host,tls,sni,ps` | `type=vmess`, `uuid`, `alter_id`, `security`, optional padding/length | Same generic transport/TLS mapper | `v`, `type`, empty aliases and vendor keys may differ; missing `aid` must not be guessed; `fm` unsupported |
| `trojan` | `trojan://password@host:port?...#name` | `type=trojan`, `password` | TLS enabled by protocol semantics; generic transports | Encrypted TLS policy must remain strict; extra URI fields and transport compatibility need tests |
| `ss` | SIP002 userinfo (base64 or plain method:password), legacy base64; optional `plugin` | `type=shadowsocks`, `method`, `password`, plugin/opts, network, UDP-over-TCP | No generic V2Ray transports | SS plugin options are nuanced; `type=tcp` and `headerType=none` are render-neutral only under precise conditions |
| `hysteria2` / `hy2` | URI userinfo becomes `password`; query may contain auth, obfs, ports, bandwidth | `type=hysteria2`, `password`, `server_ports`, `hop_interval`, `up_mbps`, `down_mbps`, `obfs`, `realm` | TLS enabled; optional SNI, ALPN, uTLS | Certificate fingerprint vs uTLS fingerprint cannot be conflated; `pinSHA256`, `fastopen`, `realm-opts` unsupported; bandwidth conversion rejects non-integer Mbps |
| `tuic` | `tuic://UUID:password@host:port?...#name` | `type=tuic`, `uuid`, `password`, `congestion_control`, `udp_relay_mode`, `zero_rtt_handshake`, `heartbeat` | TLS enabled | TUIC v4 `token` unsupported; certificate fingerprint pinning vs uTLS fingerprint must remain distinct |

### Cross-protocol field families

| Family | Source URI fields / aliases | JSON destination | Validation / important caveat |
|---|---|---|---|
| Endpoint | URI authority, `add/port` for VMess | `server`, `server_port` | Validate host, port range, authority and URL encoding |
| TLS | `security`, `tls`, `sni`, `server_name`, `alpn` | `tls.enabled`, `tls.server_name`, `tls.alpn` | Alias conflicts must be rejected rather than silently overridden |
| uTLS | `fp`, `client-fingerprint` (context-dependent `fingerprint`) | `tls.utls.fingerprint` | Certificate fingerprint `fingerprint` in HY2/TUIC is **not** interchangeable |
| REALITY | `pbk/public_key`, `sid/short_id`, `reality-opts` | `tls.reality.public_key`, `short_id` | `spx/spider_x` intentionally unsupported; do not infer `fp=chrome` |
| WS | `type/net=ws`, `host`, `path`, `ws-opts`, `ed`, `eh` | `transport.type=ws`, `path`, `headers`, early-data fields | Header handling and empty vs absent values need fixtures |
| gRPC | `type/net=grpc`, `serviceName/service_name`, `grpc-opts` | `transport.type=grpc`, `service_name`, timeouts | Vendor transport options can be incompatible |
| HTTP/H2 | `type/net=http/h2`, `path`, `host`, `method`, `headers` | `transport.type=http` | Validate expected host/path types; preserve explicit method |
| HTTPUpgrade | `type/net=httpupgrade`, `path`, `host`, `headers` | `transport.type=httpupgrade` | No silent header loss |
| XHTTP | `type/net=xhttp`, `mode`, `path`, `host`, `extra` JSON | `transport.type=xhttp`, extra fields, optional `xmux` | Mapper rejects unknown extra keys / `downloadSettings`; schema must match binary version |
| Shadowsocks plugin | `plugin`, `plugin_opts` | `plugin`, `plugin_opts` | URI plugin syntax may contain option delimiters |
| HY2 port hopping | `mport/ports/server_ports`, `hop_interval` | `server_ports`, `hop_interval` | Check range conversion and duration units |
| Metadata | URI `#fragment`, VMess `ps`, confirmed advert fields such as `Telegram` | Separate diagnostic/metadata, not outbound | Must retain provenance and `original_raw` |

## Known mismatches and design hazards

1. **Unknown handling differs by phase.** Ingest retains unknown fields; extended forwards the raw URI; standard mapper forwards unknown JSON fields; render rejects fields outside its allowlists. `Telegram` is an observed render failure on an otherwise network-qualified VLESS.
2. **`type` is overloaded.** URI `type` is a transport selection, whereas outbound JSON `type` is a protocol. The converter must discriminate by protocol and input envelope.
3. **Different parameter meaning by protocol.** `fingerprint`, `security`, `method`, `password`, `network` are not globally equivalent.
4. **Alias conflicts.** `_first_present` selects the first known spelling without checking conflicting simultaneous values. A strict parser should reject conflicting aliases.
5. **Default vs absent.** Do not turn missing security/fingerprint/alterId into guessed values; do not assume `type=""` and `type=auto` are equivalent.
6. **Extended is not a canonical JSON baseline.** It parses an unmodified URI, sometimes including extension fields which the native JSON mapper does not implement. A test of native JSON vs extended is a *differential compatibility* test, not a proof they are semantically equal.
7. **Identity / DB risk.** Current `ensure_id()` uses all original params. Removing advertisement fields before hashing changes IDs, dedup, reliability history and run observations. Do **not** modify production identity as part of the initial native mapper experiment.
8. **Raw-loss risk.** For tests, retain `original_raw`, original params and a `dropped_fields` list with values and reason. Do not silently erase or redact them from local debug storage (but protect user-supplied secrets in published reports).
9. **Unsupported transports.** Code rejects KCP, QUIC, domain socket, splitHTTP; new parser must report these as unsupported, not convert them into TCP.
10. **Security remains upstream.** The experiment must not bypass static security (including insecure TLS/cert verification rules) simply because `sing-box check` accepts the JSON.

## Experimental acceptance plan

**Phase 2 — gather empirical field inventory** (no network required):
- Read a **single matched run** of `01-parsed.jsonl`, `03-safe.jsonl`, `11-rejected-render.jsonl`, `14-published.jsonl` (and parse-error reports where available).
- Count query keys / VMess JSON keys *by protocol*, distinguish aliases and field types, count unknown fields and source distributions.
- Produce a deterministic fixture corpus (no public secret-bearing URI in committed fixtures) for representative allowed, rejected, and extension cases.

**Phase 3 — implement separately named opt-in converter**:
- `URI -> protocol-specific parser -> typed normalized connection model -> strict native JSON`.
- Explicit per-protocol allowlists and type validation. Known semantic fields retained/mapped.
- Experimental behavior: non-allowlisted fields dropped **with structured diagnostics**; retain original URI and original params untouched in the existing `ProxyConfig`.
- For recognized-but-unsupported *connection-relevant* fields, record an incompatibility and refuse to assert semantic equivalence; optionally still test on an explicit experiment flag, never silently mark it equivalent.
- Do not change `ingest.parse_uri`, `ensure_id`, dedup, SQLite or production `render` yet.

**Phase 4 — A/B on identical source identifiers**:
- A: existing extended parser, original URI.
- B: new strict native JSON outbound.
- Save SHA256 identity, backend, generated JSON, dropped fields, `sing-box check` result, latency, download, upload, exit-IP, failure reason separately.
- Compare `CORE_PASS`, `NETWORK_PASS`, throughput, latency, exit IP and compatibility by protocol/transport, without auto-fallback.
- First benchmark small stratified samples before an entire run; use the *same URI and conditions* for both backends.

## Stage gates / explicit non-goals

- No changes to `main` during this work.
- No guessing missing security parameters.
- No global switch to JSON or weakening of URI ingress validity before measurable A/B evidence.
- No automatic identity migration or rebuilding the historical SQLite database.
- **Next deliverable:** quantitative, actual-run parameter inventory and safe test corpus, followed by native converter implementation.
