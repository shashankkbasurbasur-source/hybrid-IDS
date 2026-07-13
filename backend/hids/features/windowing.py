from collections import defaultdict


def group_events_by_source_ip(events):
    grouped = defaultdict(list)
    for e in events:
        grouped[e.get("ip")].append(e)
    return grouped
