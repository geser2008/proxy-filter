# proxy-filter

A Debian-first, fully headless proxy subscription filtering pipeline.

Goals:

- ingest Plain URI lists, Base64-wrapped subscriptions, Clash YAML and sing-box JSON;
- normalize them to one canonical JSONL representation;
- reject malformed, duplicate and statically unsafe profiles before expensive tests;
- run cheap TCP reachability checks before starting a proxy core;
- use a headless core (`sing-box` by default; Xray can be added as another backend) for real proxy tests;
- measure latency, download throughput, upload throughput and exit IP without any GUI component;
- filter by configurable thresholds after every stage;
- publish per-source and merged subscriptions;
- prefer Python standard library and Debian packages; no `pip` is required.

## Architecture

```text
subscription sources
        |
        v
 download / autodetect
        |
        v
 Plain | Base64 | Clash | sing-box
        |
        v
 canonical JSONL
        |
        v
 deduplicate
        |
        v
 static security filter
        |
        v
 TCP pre-check
        |
        v
 headless core worker
   (sing-box/Xray)
        |
        +--> URL latency test --> threshold --> DROP failures
        |
        +--> download test -----> threshold --> DROP failures
        |
        +--> upload test -------> threshold --> DROP failures
        |
        +--> exit-IP test ------> DROP failures
        |
        v
 country / flag / rename
        |
        +--> source-id.txt
        +--> source-id.jsonl
        +--> all.txt
        `--> all.jsonl
```

Every expensive stage receives only survivors of the previous stage.

## Headless test worker

There is no Throne or other GUI dependency.

For each proxy candidate the worker will:

1. generate a temporary config for the selected core;
2. bind an ephemeral proxy listener to `127.0.0.1` only;
3. start the core as an unprivileged child process;
4. run test requests through that loopback listener;
5. collect latency/download/upload/exit-IP results;
6. terminate the core and remove the temporary config.

The loopback SOCKS endpoint is only an internal transport between the tester and the headless core. It is never exposed to the LAN and is not part of the published service API.

This design keeps the tester independent from GUI clients and lets us later move only the worker/core into Docker without changing ingest, filtering, JSONL or publishing logic.

## Debian packages

Base application:

```bash
sudo apt install python3 python3-yaml curl jq git nginx
```

`python3-yaml` is only required for Clash YAML input. Plain, Base64 and sing-box JSON use the Python standard library.

The proxy core is a separate external runtime. The project will detect the configured binary (`sing-box` by default). Installation instructions are kept separate because availability/version depends on the Debian release and selected repository.

## Layout

```text
/srv/proxy-filter/
├── app/        # this repository
├── config/     # local configuration
└── data/
    ├── raw/
    ├── work/
    ├── reports/
    ├── runtime/    # temporary core configs/sockets/state
    └── output/
```

Recommended service user: `proxyfilter` with no shell and no membership in `docker`, `sudo`, `jellyfin`, `qbittorrent` or other privileged groups.

## Quick start

```bash
sudo useradd --system --home /srv/proxy-filter --shell /usr/sbin/nologin proxyfilter
sudo mkdir -p /srv/proxy-filter/{app,config,data/{raw,work,reports,runtime,output}}
sudo chown -R proxyfilter:proxyfilter /srv/proxy-filter

git clone https://github.com/geser2008/proxy-filter.git /srv/proxy-filter/app
sudo cp /srv/proxy-filter/app/config.example.yaml /srv/proxy-filter/config/config.yaml
sudo chown proxyfilter:proxyfilter /srv/proxy-filter/config/config.yaml
```

Current implemented stages can be tested with:

```bash
sudo -u proxyfilter /usr/bin/python3 /srv/proxy-filter/app/proxy_filter.py \
  --config /srv/proxy-filter/config/config.yaml \
  --until tcp
```

## Canonical JSONL

One line represents one profile. Static configuration and runtime observations remain separate:

```json
{"id":"...","source":{"id":"radikal","name":"Free-v2ray-Configs","format":"base64/plain"},"config":{"protocol":"vless","server":"example.com","port":443,"name":"node","params":{}},"tests":{"security":{"status":"pass","reasons":[]},"tcp":{"status":"pass","latency_ms":42.1},"latency_ms":71.4,"download_mbps":82.3,"upload_mbps":18.9,"exit_ip":"203.0.113.10","country":"NL"},"original":{"format":"vless-uri","raw":"vless://..."}}
```

The `id` is a SHA-256 hash of the normalized connection identity and excludes display names. This provides stable deduplication and a straightforward future migration to SQLite.

## Test semantics

- **TCP pre-check** is cheap reachability only; it does not prove that the proxy works.
- **Latency** is an HTTP(S) request through the actual proxy tunnel, not ICMP ping.
- **Download** measures received bytes over elapsed time through the proxy.
- **Upload** measures transmitted bytes over elapsed time through the proxy.
- **Exit IP** is observed through an external IP endpoint and must differ from the server's direct WAN IP when that comparison is enabled.
- Speed tests are intentionally low-concurrency (normally one at a time) so candidates do not compete for the home Internet connection.

## Security model

Static policy and runtime/core validation are separate checks. A profile can be syntactically valid and reachable while still violating local policy, for example disabled certificate verification. A profile can also pass local policy but fail to start in the selected core. Both outcomes are recorded independently and rejected before subsequent expensive stages.

## Publishing

Generated files will be written atomically into `data/output`, so NetShift cannot fetch a partially-written subscription. The same output directory can be served by nginx on the LAN and optionally committed/pushed to GitHub.
