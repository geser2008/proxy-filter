#!/usr/bin/env python3
"""Non-mutating diagnostics for malformed public delta subscription rows.

Run from the proxy-filter application directory. Results are written to /tmp.
"""
import argparse
import base64
import json
import re
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from proxyfilter.ingest import parse_uri
from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.security import check_static_security
from proxyfilter.singbox_auto import SingBoxBackend

SS_PATTERN = re.compile(
    r'^(ss://[^@\s/?#]+@(?:\[[0-9A-Fa-f:.]+\]|[^:/?#\s]+):[0-9]{1,5})', re.I
)
B64_PATTERN = re.compile(r'^([A-Za-z0-9_+/=-]+)')


def repair(raw):
    if raw.startswith('ss://'):
        match = SS_PATTERN.match(raw)
        if not match:
            return None
        base = match.group(1)
        fragment = raw.partition('#')[2]
        return base + ('#' + fragment if fragment else '')
    if raw.startswith('vmess://'):
        payload = raw[8:].split('#', 1)[0]
        match = B64_PATTERN.match(payload)
        if not match:
            return None
        token = match.group(1)
        # Recover only prefixes decoding into complete, valid JSON objects.
        for end in range(len(token), 3, -1):
            candidate = token[:end]
            if '=' in candidate.rstrip('='):
                continue
            try:
                raw_bytes = base64.b64decode(
                    candidate + '=' * (-len(candidate) % 4),
                    altchars=b'-_', validate=True,
                )
                obj = json.loads(raw_bytes.decode('utf-8'))
                if not isinstance(obj, dict) or not obj.get('add') or not obj.get('port'):
                    continue
                return 'vmess://' + base64.b64encode(raw_bytes).decode('ascii')
            except (ValueError, UnicodeError, TypeError):
                pass
        return None
    return None


def read_checkpoint_ids(path):
    ids = set()
    if not path.is_file():
        return ids
    with path.open(encoding='utf-8') as f:
        for line in f:
            if line.strip():
                proxy = ProxyConfig.from_dict(json.loads(line))
                ids.add(proxy.ensure_id())
    return ids


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        '--errors', type=Path,
        default=Path('../data/reports/delta-parse-errors.json'),
    )
    ap.add_argument('--work', type=Path, default=Path('../data/work'))
    ap.add_argument('--max-network', type=int, default=25,
                    help='Maximum safe unseen candidates to test; 0 means all')
    ap.add_argument('--backend', choices=['extended', 'standard'], default='extended')
    ap.add_argument('--curl-timeout', type=int, default=12)
    args = ap.parse_args()

    rows = json.loads(args.errors.read_text(encoding='utf-8'))
    stats = Counter()
    unique = {}
    failures = []
    for item in rows:
        stats['input_errors'] += 1
        candidate = repair(item.get('raw', ''))
        if candidate is None:
            stats['unrecoverable'] += 1
            continue
        try:
            proxy = parse_uri(candidate, SourceInfo('delta', 'delta', 'plain'))
            stats['parse_pass'] += 1
        except Exception as exc:
            stats['parse_fail_after_repair'] += 1
            failures.append({'line': item.get('line'), 'error': str(exc)})
            continue
        unique.setdefault(proxy.ensure_id(), proxy)

    stats['unique_recovered'] = len(unique)
    safe = {}
    security_reasons = Counter()
    for pid, proxy in unique.items():
        ok, reasons = check_static_security(proxy)
        if ok:
            safe[pid] = proxy
        else:
            security_reasons.update(reasons)
    stats['unique_security_pass'] = len(safe)
    stats['unique_security_reject'] = len(unique) - len(safe)

    checkpoint_paths = [
        args.work / name for name in (
            '01-parsed.jsonl', '02-unique.jsonl', '03-safe.jsonl',
            '03-rejected-security.jsonl',
        )
    ]
    checkpoints = {}
    for path in checkpoint_paths:
        if path.is_file():
            checkpoints[path.name] = read_checkpoint_ids(path)
        else:
            print(f'WARNING: checkpoint missing: {path}')
    prior = set().union(*checkpoints.values()) if checkpoints else set()
    unseen = {pid: proxy for pid, proxy in safe.items() if pid not in prior}
    stats['safe_seen_in_checkpoints'] = len(safe) - len(unseen)
    stats['safe_unseen_in_checkpoints'] = len(unseen)

    print('=== RECOVERY ===')
    for key in (
        'input_errors', 'unrecoverable', 'parse_pass',
        'parse_fail_after_repair', 'unique_recovered',
        'unique_security_pass', 'unique_security_reject',
        'safe_seen_in_checkpoints', 'safe_unseen_in_checkpoints',
    ):
        print(f'{key}: {stats[key]}')
    print('security_reasons:', dict(security_reasons))
    print('checkpoints:', {name: len(ids) for name, ids in checkpoints.items()})
    print('Caution: checkpoints from different runs are not a same-run comparison.')

    checked = Counter()
    results = []
    candidates = list(unseen.items())
    if args.max_network > 0:
        candidates = candidates[:args.max_network]

    with tempfile.TemporaryDirectory(prefix='delta-recovered-') as tmp:
        backend = SingBoxBackend(
            command='sing-box', backend_mode=args.backend, runtime_dir=tmp
        )
        for index, (pid, proxy) in enumerate(candidates, 1):
            print(
                f'[{index}/{len(candidates)}] {pid[:12]} '
                f'{proxy.protocol} {proxy.server}:{proxy.port}',
                flush=True,
            )
            session = None
            outcome = {
                'id': pid, 'protocol': proxy.protocol,
                'server': proxy.server, 'port': proxy.port,
                'original_raw': proxy.original_raw,
            }
            try:
                ok, err = backend.validate(proxy)
                if not ok:
                    outcome.update(result='CORE_FAIL', error=str(err)[:500])
                    checked['CORE_FAIL'] += 1
                else:
                    checked['CORE_PASS'] += 1
                    session = backend.start(proxy)
                    response = subprocess.run(
                        [
                            'curl', '-sS', '-o', '/dev/null',
                            '--proxy', session.http_url,
                            '--connect-timeout', '7',
                            '--max-time', str(args.curl_timeout),
                            '-w', '%{http_code}',
                            'https://www.gstatic.com/generate_204',
                        ],
                        capture_output=True, text=True,
                        timeout=args.curl_timeout + 6,
                    )
                    passed = (
                        response.returncode == 0
                        and response.stdout.strip() == '204'
                    )
                    label = (
                        'NETWORK_PASS' if passed
                        else f'NETWORK_FAIL_{response.returncode}'
                    )
                    checked[label] += 1
                    outcome.update(
                        result=label,
                        http=response.stdout.strip(),
                        error=response.stderr.strip()[:500],
                    )
            except Exception as exc:
                checked['RUNTIME_FAIL'] += 1
                outcome.update(
                    result='RUNTIME_FAIL',
                    error=f'{type(exc).__name__}: {exc}'[:500],
                )
            finally:
                if session is not None:
                    backend.stop(session)
            results.append(outcome)
            print(
                '  ' + outcome['result'] +
                (' ' + outcome.get('error', '')[:140]
                 if outcome.get('error') else ''),
                flush=True,
            )

    output_path = Path('/tmp/delta-recovered-network.json')
    output_path.write_text(
        json.dumps(
            {
                'summary': dict(stats),
                'security_reasons': dict(security_reasons),
                'network': dict(checked),
                'results': results,
                'repair_failures': failures,
            },
            ensure_ascii=False, indent=2,
        ),
        encoding='utf-8',
    )
    print('=== NETWORK SUMMARY ===')
    for name, count in sorted(checked.items()):
        print(f'{name}: {count}')
    print('results_file:', output_path)


if __name__ == '__main__':
    main()
