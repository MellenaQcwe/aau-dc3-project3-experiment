#!/usr/bin/env python3
"""Analyze Cooja PCAP + COOJA.testlog into reproducible OSCORE baseline CSVs.
Requires tshark (sudo apt install tshark); Python standard library only.
"""
import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

FIELDS = ['frame.number', 'frame.time_epoch', 'frame.len', 'wpan.src16', 'wpan.src64', 'ipv6.src', 'ipv6.dst', 'coap.code', 'frame.protocols']
DEFAULT_PATTERNS = {
    'command_sent': r'\b(?:OSCORE_REQUEST_SEND|PAIRWISE_OSCORE_SEND|LIGHT_ON_SENT)\b',
    'authenticated_received': r'\b(?:OSCORE_REQUEST_RECEIVED|OSCORE_AUTH_OK|AUTHENTICATED_LIGHT_ON)\b',
    'authentication_failed': r'\b(?:OSCORE_DECRYPTION_FAILED|OSCORE_AUTH_FAIL|AUTHENTICATION_FAILED|DECRYPT_FAIL)\b',
    'experiment_end': r'\bPAIRWISE_OSCORE_END\b',
}
LOG_TIME = re.compile(r'^\s*(\d+(?:\.\d+)?)\s*(?:\t|\s+)ID\s*:\s*(\d+)\s*(?:\t|\s+)(.*)$')

def tshark_frames(path):
    if not shutil.which('tshark'):
        raise RuntimeError('tshark not found. Install with: sudo apt install tshark')
    cmd = ['tshark', '-r', str(path), '-n', '-T', 'fields', '-E', 'separator=\t', '-E', 'occurrence=f']
    for field in FIELDS:
        cmd += ['-e', field]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode:
        raise RuntimeError(f'tshark failed for {path}: {proc.stderr.strip()}')
    rows = []
    for line in proc.stdout.splitlines():
        vals = (line.split('\t') + [''] * len(FIELDS))[:len(FIELDS)]
        rec = dict(zip(FIELDS, vals))
        try:
            rec['frame.len'] = int(rec['frame.len'])
            rec['frame.time_epoch'] = float(rec['frame.time_epoch'])
            rec['frame.number'] = int(rec['frame.number'])
        except ValueError:
            continue
        rows.append(rec)
    return rows

def log_events(path, patterns):
    events = []
    for line_no, line in enumerate(path.read_text(encoding='utf-8', errors='replace').splitlines(), 1):
        match = LOG_TIME.match(line)
        timestamp = match.group(1) if match else ''
        mote_id = match.group(2) if match else ''
        message = match.group(3) if match else line
        matched = [name for name, rx in patterns.items() if rx.search(message)]
        for name in matched:
            events.append({'line_number': line_no, 'simulation_time_raw': timestamp,
                           'mote_id': mote_id, 'event': name, 'message': message.strip()})
    return events

def write_csv(path, fieldnames, rows):
    with path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--manifest', type=Path, required=True, help='JSON list of runs, each with name, mode, receivers, pcap, log')
    ap.add_argument('--out', type=Path, default=Path('baseline_results'))
    ap.add_argument('--patterns', type=Path, help='Optional JSON mapping event names to Python regex patterns')
    args = ap.parse_args()
    runs = json.loads(args.manifest.read_text(encoding='utf-8'))
    if not isinstance(runs, list) or not runs:
        ap.error('Manifest must contain a nonempty JSON list')
    patterns = dict(DEFAULT_PATTERNS)
    if args.patterns:
        patterns.update(json.loads(args.patterns.read_text(encoding='utf-8')))
    compiled = {key: re.compile(value, re.IGNORECASE) for key, value in patterns.items()}
    args.out.mkdir(parents=True, exist_ok=True)
    summaries = []
    all_frames = []
    all_events = []
    for run in runs:
        name = str(run['name'])
        pcap = Path(run['pcap']).expanduser()
        log = Path(run['log']).expanduser()
        if not pcap.is_absolute():
            pcap = args.manifest.parent / pcap
        if not log.is_absolute():
            log = args.manifest.parent / log
        if not pcap.is_file() or not log.is_file():
            raise FileNotFoundError(f'{name}: missing PCAP or testlog: {pcap}, {log}')
        frames = tshark_frames(pcap)
        events = log_events(log, compiled)
        counts = Counter(e['event'] for e in events)
        lengths = [f['frame.len'] for f in frames]
        times = [f['frame.time_epoch'] for f in frames]
        total = sum(lengths)
        protocols = ('wpan', '6lowpan', 'ipv6', 'udp', 'coap', 'data', 'oscore', 'icmpv6')
        protocol_stats = {}
        for proto in protocols:
            selected = [f for f in frames if proto in f['frame.protocols'].split(':')]
            protocol_stats[f'{proto}_frames'] = len(selected)
            protocol_stats[f'{proto}_bytes'] = sum(f['frame.len'] for f in selected)
        for frame in frames:
            all_frames.append({'run': name, 'mode': run.get('mode', 'pairwise'),
                               'receivers': run['receivers'], **frame})
        for event in events:
            all_events.append({'run': name, 'mode': run.get('mode', 'pairwise'),
                               'receivers': run['receivers'], **event})
        summaries.append({
            'run': name, 'mode': run.get('mode', 'pairwise'), 'receivers': run['receivers'],
            'pcap_packets': len(frames), 'pcap_bytes': total,
            **protocol_stats,
            'pcap_avg_frame_bytes': round(total / len(frames), 2) if frames else '',
            'pcap_first_epoch_s': min(times) if times else '',
            'pcap_last_epoch_s': max(times) if times else '',
            'pcap_span_s': round(max(times) - min(times), 6) if times else '',
            'command_sent_log_matches': counts['command_sent'],
            'authenticated_received_log_matches': counts['authenticated_received'],
            'authentication_failed_log_matches': counts['authentication_failed'],
            'experiment_end_log_matches': counts['experiment_end'],
            'matched_log_events': len(events),
            'pcap_file': str(pcap), 'log_file': str(log),
        })
        print(f"{name}: total {len(frames)} frames/{total} bytes; "
              f"OSCORE {protocol_stats['oscore_frames']} frames/{protocol_stats['oscore_bytes']} bytes; "
              f"CoAP {protocol_stats['coap_frames']} frames/{protocol_stats['coap_bytes']} bytes; "
              f"ICMPv6 {protocol_stats['icmpv6_frames']} frames/{protocol_stats['icmpv6_bytes']} bytes")
    write_csv(args.out / 'baseline_summary.csv', list(summaries[0]), summaries)
    write_csv(args.out / 'baseline_packets.csv',
              ['run', 'mode', 'receivers'] + FIELDS, all_frames)
    write_csv(args.out / 'baseline_events.csv',
              ['run', 'mode', 'receivers', 'line_number', 'simulation_time_raw', 'mote_id', 'event', 'message'], all_events)
    print(f'Wrote 3 CSV files to {args.out.resolve()}')
    if not any(x['matched_log_events'] for x in summaries):
        print('WARNING: no application event patterns matched. Inspect logs and customize --patterns.', file=sys.stderr)
    print('NOTE: Protocol categories overlap; byte counts are full captured frame lengths, not protocol payload sizes.')

if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, re.error) as exc:
        sys.exit(f'ERROR: {exc}')
