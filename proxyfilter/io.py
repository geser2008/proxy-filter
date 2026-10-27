from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

from .core_category import annotate_core_category
from .model import ProxyConfig
from .summary_diagnostics import enrich_summary


def fetch_url(url: str, timeout: float = 30.0) -> bytes:
    req = Request(url, headers={"User-Agent": "proxy-filter/0.1"})
    with urlopen(req, timeout=timeout) as response:
        return response.read()


def write_jsonl(path: Path, proxies: list[ProxyConfig]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        for proxy in proxies:
            annotate_core_category(proxy)
            fh.write(json.dumps(proxy.to_dict(), ensure_ascii=False, separators=(",", ":")) + "\n")
    os.replace(tmp, path)


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = enrich_summary(path, data)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)