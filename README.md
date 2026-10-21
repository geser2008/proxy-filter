# proxy-filter

A Debian-first proxy subscription filtering pipeline.

Goals:

- ingest Plain URI lists, Base64-wrapped subscriptions, Clash YAML and sing-box JSON;
- normalize them to one canonical JSONL representation;
- reject malformed, duplicate and statically unsafe profiles before expensive tests;
- optionally run a cheap TCP pre-check;
- pass only survivors to Throne for latency, speed and exit-IP tests;
- filter by latency/download/upload thresholds;
- publish per-source and merged subscriptions;
- use Debian packages and Python standard library wherever possible; no `pip` is required.

## Status

Early MVP. Ingest/normalization, URI round-trip, static filtering, TCP pre-check and output generation are implemented first. The Throne adapter is deliberately isolated so its CLI/API mapping can be adjusted to the exact installed Throne version without changing the rest of the pipeline.

## Debian packages

```bash
sudo apt install python3 python3-yaml jq git nginx
```

`python3-yaml` is only required for Clash YAML input. Plain, Base64 and sing-box JSON use the Python standard library.

## Layout

```text
/srv/proxy-filter/
├── app/        # this repository
├── config/     # local configuration
└── data/
    ├── raw/
    ├── work/
    ├── reports/
    └── output/
```

Recommended service user: `proxyfilter` with no shell and no membership in `docker`, `sudo`, `jellyfin`, `qbittorrent` or other privileged groups.

## Pipeline

```text
source
  -> download
  -> autodetect format
  -> normalize to canonical JSONL
  -> deduplicate
  -> static security filter
  -> TCP pre-check
  -> Throne latency
  -> latency threshold
  -> Throne speed
  -> download/upload thresholds
  -> Throne IP
  -> country/flag rename
  -> per-source subscription
  -> merged subscription
  -> atomic publish
```

Every stage receives only profiles that passed the preceding stage. Rejected entries remain in reports with a rejection reason but are not passed to more expensive tests.

## Quick start

```bash
sudo useradd --system --home /srv/proxy-filter --shell /usr/sbin/nologin proxyfilter
sudo mkdir -p /srv/proxy-filter/{app,config,data/{raw,work,reports,output}}
sudo chown -R proxyfilter:proxyfilter /srv/proxy-filter

git clone https://github.com/geser2008/proxy-filter.git /srv/proxy-filter/app
sudo cp /srv/proxy-filter/app/config.example.yaml /srv/proxy-filter/config/config.yaml
sudo chown proxyfilter:proxyfilter /srv/proxy-filter/config/config.yaml
```

Run the ingest/filter stages:

```bash
sudo -u proxyfilter /usr/bin/python3 /srv/proxy-filter/app/proxy_filter.py \
  --config /srv/proxy-filter/config/config.yaml \
  --until tcp
```

The initial example contains the two public sources discussed during design.

## Canonical JSONL

One line represents one profile. Configuration and runtime tests are kept logically separate:

```json
{"id":"...","source":{"id":"radikal","name":"Free-v2ray-Configs","format":"base64/plain"},"config":{"protocol":"vless","server":"example.com","port":443,"name":"node","params":{}},"tests":{"security":{"status":"pass","reasons":[]},"tcp":{"status":"pass","latency_ms":42.1},"latency_ms":null,"download_mbps":null,"upload_mbps":null,"exit_ip":null,"country":null},"original":{"format":"vless-uri","raw":"vless://..."}}
```

The `id` is a SHA-256 hash of the normalized connection identity and excludes the display name. This allows stable deduplication and later migration to SQLite.

## Throne

The project keeps Throne behind `proxyfilter/throne.py`. The rest of the application never depends directly on Throne CLI syntax or its JSON field names. Once the exact output of the installed version is captured for latency/speed/IP, only this adapter needs adjustment.

## Output

Generated files are written atomically into `data/output` so NetShift cannot fetch a partially-written subscription.

Planned output:

```text
source-id.txt
all.txt
source-id.jsonl
all.jsonl
```

## Security model

Static checks are intentionally separate from Throne/core validation. A profile can be syntactically valid and reachable while still violating local policy, e.g. disabled certificate verification. Conversely, a profile can satisfy local policy but be unsupported by the installed core. Both outcomes are recorded separately.
