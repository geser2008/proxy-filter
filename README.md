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
├── config/
│   ├── config.yaml     # pipeline/runtime settings
│   └── sources.yaml    # subscription sources
└── data/
    ├── raw/
    ├── work/
    ├── reports/
    ├── history/    # optional SQLite long-term history
    ├── runtime/    # temporary core configs/sockets/state
    └── output/
```

Recommended service user: `proxyfilter` with no shell and no membership in `docker`, `sudo`, `jellyfin`, `qbittorrent` or other privileged groups.

## Quick start

```bash
sudo useradd --system --home /srv/proxy-filter --shell /usr/sbin/nologin proxyfilter
sudo mkdir -p /srv/proxy-filter/{app,config,data/{raw,work,reports,history,runtime,output}}
sudo chown -R proxyfilter:proxyfilter /srv/proxy-filter

git clone https://github.com/geser2008/proxy-filter.git /srv/proxy-filter/app
sudo cp /srv/proxy-filter/app/config.example.yaml /srv/proxy-filter/config/config.yaml
sudo cp /srv/proxy-filter/app/sources.example.yaml /srv/proxy-filter/config/sources.yaml
sudo chown proxyfilter:proxyfilter /srv/proxy-filter/config/{config.yaml,sources.yaml}
```

Current implemented stages can be tested with:

```bash
sudo -u proxyfilter /usr/bin/python3 /srv/proxy-filter/app/proxy_filter.py \
  --config /srv/proxy-filter/config/config.yaml \
  --sources /srv/proxy-filter/config/sources.yaml \
  --until tcp
```

`--sources` is optional for backward compatibility. If it is omitted, the program reads the legacy top-level `sources:` list from `config.yaml`.

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

## Availability history

Long-term per-source history is stored in SQLite while JSONL files remain the runtime/checkpoint format. Enable automatic recording of ordinary full publish runs in `config.yaml`:

```yaml
history:
  enabled: true
  database: history/proxy-history.sqlite3
  store_details: failures
```

A relative `database` path is resolved below `paths.data_dir`. The default path is `data/history/proxy-history.sqlite3`.

`history` is also an explicit non-filtering stage after `publish`:

```bash
python3 proxy_filter.py \
  --config ../config/config.yaml \
  --sources ../config/sources.yaml \
  --until history
```

To import an already completed `work/<source>/` snapshot without rerunning network tests:

```bash
python3 proxy_filter.py \
  --config ../config/config.yaml \
  --sources ../config/sources.yaml \
  --history-import \
  --source radikal
```

The equivalent stage form is:

```bash
python3 proxy_filter.py \
  --config ../config/config.yaml \
  --sources ../config/sources.yaml \
  --source radikal \
  --resume-from publish \
  --until history
```

A standalone import requires both `02-unique.jsonl` and `12-published.jsonl`. Its run id is derived from the snapshot contents, so importing unchanged files again is idempotent and does not duplicate history. A failed source fetch records a failed run but does not mark previously known proxies absent.

The database contains:

- `runs`: one row per source/run with stage survivor counts and source-level errors;
- `proxy_observations`: append-only per-proxy observations with availability, stage result, latency/speed, reliability, exit IP and geo fields;
- `proxy_source_state`: current aggregate state per `(source_id, proxy_id)`, including first/last seen, availability counts, absence counts and current streak.

`availability_state` distinguishes `available`, `degraded`, `below_threshold`, `unavailable`, and `absent`.

Examples:

```bash
sqlite3 /srv/proxy-filter/data/history/proxy-history.sqlite3 \
  "SELECT source_id,status,finished_at,published_count FROM runs ORDER BY finished_at DESC LIMIT 20;"
```

```bash
sqlite3 /srv/proxy-filter/data/history/proxy-history.sqlite3 \
  "SELECT source_id,availability_state,COUNT(*) FROM proxy_observations GROUP BY source_id,availability_state;"
```

```bash
sqlite3 /srv/proxy-filter/data/history/proxy-history.sqlite3 \
  "SELECT proxy_id,seen_count,available_count,absent_count,current_streak,current_streak_state FROM proxy_source_state WHERE source_id='radikal' ORDER BY available_count DESC LIMIT 20;"
```

`history.store_details` accepts `none`, `failures`, or `all`. Normalized columns are always stored; this option controls the additional detailed JSON snapshot.

## Security model

Static policy and runtime/core validation are separate checks. A profile can be syntactically valid and reachable while still violating local policy, for example disabled certificate verification. A profile can also pass local policy but fail to start in the selected core. Both outcomes are recorded independently and rejected before subsequent expensive stages.

## Publishing

Generated files will be written atomically into `data/output`, so NetShift cannot fetch a partially-written subscription. The same output directory can be served by nginx on the LAN and optionally committed/pushed to GitHub.
