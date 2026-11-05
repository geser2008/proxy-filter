# sing-box-extended link parser: source audit and field inventory

Date: 2026-11-05. **Experimental research only.** No production pipeline changes.

## Source provenance

- Upstream: `shtorm-7/sing-box-extended`, tag `v1.14.3-extended-2.7.3`.
- Inspected implementation files under `parser/link/`: `vless.go`, `vmess.go`, `shadowsocks.go`, `trojan.go`, `hysteria2.go`, `tuic.go`.
- Lite build inspected: `MANCrimSon/sing-box-extended-lite`, `.github/workflows/build-and-release.yml`. Workflow checks out the upstream tag and builds `./cmd/sing-box` using `with_quic,with_dhcp,with_wireguard,with_utls,with_clash_api,badlinkname,tfogo_checklinkname0`. This is a build of upstream code, **not a separate parser implementation**. Build-tag-specific behavior still requires confirmation against the installed executable.
- The last pipeline reported `sing-box version 1.14.3-extended-2.7.3-lite`. Confirm the actual binary's provenance with build metadata when available.

## Actual parser behavior (direct source inspection)

| Protocol | Recognized semantics | Silent/discarded data and hazards |
|---|---|---|
| VLESS | UUID, server/port, `type=ws/http/grpc/xhttp`, TLS/REALITY, SNI, ALPN, uTLS `fp`, `flow`, `pbk/sid`, TFO | Arbitrary query keys fall through unhandled, including `Telegram`; `flow` only recognized as `xtls-rprx-vision`; aliases `serviceName/sni/peer` can overwrite each other via randomized Go map iteration; `extra` for XHTTP is Base64URL JSON, and decode/unmarshal failures can be ignored |
| VMess | `id/add/port/ps/scy/aid`, transport WS, H2, TCP-HTTP, gRPC, TLS, `fp`, XUDP and TFO | Nonstandard VMess JSON keys ignored; `aid` parse error ignored (`strconv.Atoi`); `scy` defaults to `auto`; exact outer Base64 decoding is performed elsewhere in parser pipeline |
| SS | Userinfo method/password; `plugin` options | Other query keys not used; examined function expects decoded URL userinfo (upstream preprocessing may handle SIP002/Base64) |
| Trojan | Password, TLS, SNI/ALPN/`fp`, `type=ws/grpc`, TFO | Other transports and unknown query keys not represented; aliases `serviceName/sni/peer` overwritten by Go map iteration |
| Hysteria2 | Password, server, default port 443, `up/down`, `obfs` / `obfs-password`, insecure | `up/down` conversion errors ignored; many fields familiar from other HY2 implementations are not consumed in inspected handler |
| TUIC | UUID/password, server, TLS, congestion control, UDP relay, UDP-over-stream, zero-RTT, heartbeat, SNI/ALPN, insecure, TFO | Unknown keys ignored; `congestion_control=cubic` suppressed as default; when `udp_over_stream=true`, UDP relay mode is cleared |

### Specific comparison implications

1. **Extended dropping an unknown key is not proof it is safely ignorable** in other clients. `Telegram` appears to be advertising metadata in the observed VLESS; its omission in the upstream VLESS handler is confirmed.
2. Some aliases and defaults in extended **change semantics or conceal malformed input**. Do not blindly reproduce this behavior in the new JSON mapper. Prefer deterministic precedence and validation of conflicts.
3. Extended link parser and native JSON mapper expose **different feature subsets**. Successful `type=parser` does not guarantee an equivalent JSON outbound from our mapper or vice versa.
4. For XHTTP, the upstream VLESS handler expects Base64URL JSON in `extra`; the current proxy-filter mapper tries JSON text for its own `extra`. This format discrepancy should be investigated with fixtures before marking a conversion equivalent.
5. For VLESS, `flow` handling and unsupported transports require per-field diagnostics, not fallbacks that silently change a connection.
6. The current upstream VLESS/Trojan handler iterates Go maps; where aliases affect the same destination, results may be nondeterministic.
7. `sing-box check` validates the assembled outbound, not equivalence with the original URI.

## Empirical inventory from user-uploaded last-run artifacts

Available snapshots in this conversation: `14-published.jsonl` with 67 rows and `11-rejected-render.jsonl` with one row. This is **not** the whole 17,964-input dataset.

**Published (67):**
- VLESS: 37; most frequent params: `security/sni/uuid` 37 each, `fp` 36, `type` 32, `flow/pbk` 27, `encryption` 18.
- Trojan: 24; `sni/password` 24, `security` 23, `type` 20, `headerType` 18, `fp` 9.
- Shadowsocks: 6; `method/password` 6 each.
- VMess, HY2, TUIC: none in the published subset. **Do not infer absence from ingest**.

**Rejected render (1):** VLESS with unfamiliar `Telegram` query key. The field is not referenced by the inspected VLESS upstream `switch`, so the extended link parser can ignore it while our strict renderer rejects it.

These counts describe **survivor-biased output**, not prevalence of fields in the input feeds.

## Phase 2 reproducible inventory tool

Run from `app`:

```bash
python3 ../tools/audit_uri_fields.py \
  --work ../data/work \
  --output /tmp/proxy-filter-uri-field-inventory.json
```

It reads `01-parsed.jsonl`, `03-safe.jsonl`, `11-rejected-render.jsonl`, `14-published.jsonl`; prints by-stage/by-protocol totals; saves key frequencies and value **types**, without raw values, UUIDs, passwords or URI strings. Its `known-vocabulary` classification is descriptive and not a validated sing-box schema. The full dataset must be processed locally on the user's laptop before drawing conclusions.

## Next development gate

- Collect full-run inventory and verify which URI fields are connection-relevant using upstream and version-specific JSON option types.
- Build typed per-protocol field registries and deterministic alias conflict handling.
- Implement a separately selected native JSON mapper that records dropped fields without altering `ProxyConfig.params`, `original_raw` or IDs.
- A/B against `type=parser`, retaining static security, measuring actual connections and speeds.
