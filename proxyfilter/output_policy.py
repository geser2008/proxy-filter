from __future__ import annotations

from .reliability import annotate_download_reliability
from .render import render_proxy


def render_proxies(proxies, cfg):
    output_cfg = cfg.get("output", {})

    rename_template = str(output_cfg.get("rename_template", "{flag} [{source}] {name}"))
    include_original_name = bool(output_cfg.get("include_original_name", True))
    include_reliability_in_name = bool(output_cfg.get("include_stream_reliability", True))

    if (
        include_reliability_in_name
        and "{stream_reliability}" not in rename_template
        and "{reliability}" not in rename_template
    ):
        rename_template += " | reliability:{stream_reliability}"

    render_ok, render_rejected = [], []

    for proxy in proxies:
        reliability = annotate_download_reliability(proxy)

        # Reliability is a publication class, not a filtering criterion.
        # Degraded proxies stay eligible for all.txt and are later separated
        # into unstable.txt after the global diversity selection.
        result = render_proxy(
            proxy,
            rename_template=rename_template,
            include_original_name=include_original_name,
        )
        proxy.tests.render = {
            "status": "pass" if result.ok else "fail",
            "name": result.name,
            "uri": result.uri,
            "error": result.error,
            "stream_reliability": reliability["status"],
        }
        if result.ok:
            proxy.tests.status = "render_pass"
            render_ok.append(proxy)
        else:
            proxy.tests.status = "rejected_render"
            render_rejected.append(proxy)

    return render_ok, render_rejected
