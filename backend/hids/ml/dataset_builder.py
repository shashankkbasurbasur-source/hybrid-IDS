"""
Real Auth-Log Dataset Builder
================================
PRIMARY, production training data source. Builds (events, label)
window pairs from REAL auth.log files plus a companion label file, so
the HIDS model is trained on genuine SSH authentication behavior
instead of generated examples.

Inputs:
  - one or more raw auth-log files (auth.log / secure format)
  - a labels CSV mapping each SOURCE IP to a ground-truth label:
    0 = normal, 1 = attack

labels.csv format:
    ip,label
    192.168.1.50,1
    10.0.0.4,0
    203.0.113.9,1
"""

import csv
from collections import defaultdict

from backend.hids.collector.parser import AuthLogParser


def load_labels(labels_csv_path: str) -> dict:
    labels = {}
    with open(labels_csv_path, "r", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or "ip" not in reader.fieldnames or "label" not in reader.fieldnames:
            raise ValueError(f"{labels_csv_path} must have header 'ip,label' — got {reader.fieldnames}")
        for row in reader:
            ip = row["ip"].strip()
            label = int(row["label"].strip())
            if label not in (0, 1):
                raise ValueError(f"Label for {ip} must be 0 or 1, got {row['label']}")
            labels[ip] = label
    return labels


def build_dataset_from_logs(log_file_paths: list, labels_csv_path: str) -> list:
    """
    Groups real log events by source IP, pairs each IP's window with
    its label. Returns [(events, label), ...] — a drop-in replacement
    for the old generate_dataset() shape.
    """
    parser = AuthLogParser()
    labels = load_labels(labels_csv_path)

    events_by_ip = defaultdict(list)
    for log_path in log_file_paths:
        with open(log_path, "r") as f:
            for line in f:
                event = parser.parse_line(line)
                if event:
                    events_by_ip[event["ip"]].append(event)

    dataset = []
    skipped = []
    for ip, events in events_by_ip.items():
        if ip not in labels:
            skipped.append(ip)
            continue
        dataset.append((events, labels[ip]))

    if skipped:
        preview = skipped[:10]
        print(f"[!] {len(skipped)} source IP(s) had no label in {labels_csv_path} and were skipped: "
              f"{preview}{' ...' if len(skipped) > 10 else ''}")

    if not dataset:
        raise ValueError(
            "No labeled windows produced. Check that labels_csv_path contains "
            "IPs that actually appear in the provided log files."
        )

    return dataset