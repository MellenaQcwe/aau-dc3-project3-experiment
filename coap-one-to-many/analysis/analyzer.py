#!/usr/bin/env python3
"""Summarize Cooja PCAPs. Requires tshark in PATH."""
import argparse
import csv
import re
import subprocess
from pathlib import Path

FIELDS = ['frame.number', 'frame.len', 'coap.code', 'coap.type', 'coap.mid']

def tshark_rows(path, display_filter=None):
    cmd = ['tshark', '-r', str(path)]
    if display_filter:
        cmd += ['-Y', display_filter]
    cmd += ['-T', 'fields', '-E', 'separator=,', '-E', 'quote=d']
    for field in FIELDS:
        cmd += ['-e', field]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'tshark failed')
    return list(csv.DictReader(result.stdout.splitlines(), fieldnames=FIELDS))

def code_number(value):
    """CoAP code display may be numeric (2, 68) or dotted (0.02, 2.04)."""
    if not value:
        return None
    v = value.split(',')[0].strip()
    if re.fullmatch(r'\d+\.\d{1,2}', v):
        major, minor = map(int, v.split('.'))
        return major * 32 + minor
    try:
        return int(v, 0)
    except ValueError:
        return None

def summarize(path):
    all_frames = tshark_rows(path)
    coap_frames = tshark_rows(path, 'coap')
    codes = [code_number(r['coap.code']) for r in coap_frames]
    requests = sum(c is not None and 1 <= c <= 31 for c in codes)
    responses = sum(c is not None and 64 <= c <= 191 for c in codes)
    errors = sum(c is not None and 128 <= c <= 191 for c in codes)
    total_bytes = sum(int(r['frame.len'] or 0) for r in all_frames)
    coap_bytes = sum(int(r['frame.len'] or 0) for r in coap_frames)
    match = re.search(r'_n(\d+)', path.stem)
    return {
        'capture': path.name,
        'receivers': int(match.group(1)) if match else '',
        'captured_frames': len(all_frames),
        'captured_frame_bytes': total_bytes,
        'decoded_coap_frames': len(coap_frames),
        'decoded_coap_frame_bytes': coap_bytes,
        'decoded_coap_requests': requests,
        'decoded_coap_responses': responses,
        'decoded_coap_error_responses': errors,
        'unclassified_coap_frames': len(coap_frames) - requests - responses,
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('pcap_dir', type=Path)
    parser.add_argument('--output', type=Path, default=Path('results.csv'))
    args = parser.parse_args()
    files = sorted(p for p in args.pcap_dir.iterdir() if p.suffix.lower() in ('.pcap', '.pcapng'))
    if not files:
        parser.error('No .pcap or .pcapng files found')
    rows = [summarize(p) for p in files]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    for row in rows:
        print(f"{row['capture']} ({row['receivers']} receivers): frames={row['captured_frames']}, "
              f"CoAP frames={row['decoded_coap_frames']}, "
              f"CoAP requests={row['decoded_coap_requests']}, "
              f"responses={row['decoded_coap_responses']}, "
              f"CoAP frame bytes={row['decoded_coap_frame_bytes']}, "
              f"all-frame bytes={row['captured_frame_bytes']}")
    print(f'Wrote {args.output}')

if __name__ == '__main__':
    main()