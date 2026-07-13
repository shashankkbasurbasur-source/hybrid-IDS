"""
Auth Log Feature Extractor
===========================
Converts a window of normalized auth-log events into the production
HIDS feature vector defined in feature_schema.py.
"""

from datetime import datetime
from collections import defaultdict

from backend.hids.features.feature_schema import FEATURE_VECTOR_LENGTH, empty_vector

_PLACEHOLDER_YEAR = 2000  # log lines have no year; used only for relative deltas


def _parse_ts(event: dict):
    try:
        ts = f"{_PLACEHOLDER_YEAR} {event['timestamp']}"
        return datetime.strptime(ts, "%Y %b %d %H:%M:%S")
    except (KeyError, ValueError):
        return None


class AuthLogFeatureExtractor:
    def extract(self, events: list, seen_ips_before: set = None) -> list:
        """
        seen_ips_before: IPs observed in prior windows, used for
        'new_ip_count'. Omit for cold start / manual analysis of a
        single uploaded file.
        """
        seen_ips_before = seen_ips_before or set()
        vector = empty_vector()

        if not events:
            return vector

        total_events = len(events)
        fails = [e for e in events if e.get("event_type") == "auth_fail"]
        successes = [e for e in events if e.get("event_type") == "auth_success"]
        ips = [e.get("ip") for e in events if e.get("ip")]
        users = [e.get("user") for e in events if e.get("user")]
        unique_ips = set(ips)
        unique_users = set(users)

        vector[0] = len(fails)
        vector[1] = len(successes)
        vector[2] = len(unique_ips)
        vector[3] = len(unique_users)
        vector[4] = self._max_fail_streak(events)
        vector[5] = self._success_after_failure(events)
        vector[6] = self._avg_time_between(events)
        vector[7] = len(fails) / total_events if total_events else 0.0
        vector[8] = sum(1 for e in events if e.get("user") == "root")
        vector[9] = sum(1 for e in events if e.get("invalid_user"))
        vector[10] = total_events
        vector[11] = len(unique_ips - seen_ips_before)
        ports = [e.get("port") for e in events if e.get("port")]
        vector[12] = len(set(ports))
        vector[13] = sum(1 for e in events if e.get("auth_method") == "password")
        vector[14] = sum(1 for e in events if e.get("auth_method") == "publickey")

        assert len(vector) == FEATURE_VECTOR_LENGTH
        return vector

    @staticmethod
    def _max_fail_streak(events: list) -> int:
        per_ip_events = defaultdict(list)
        for e in events:
            per_ip_events[e.get("ip")].append(e)

        max_streak = 0
        for ip, evts in per_ip_events.items():
            streak = 0
            best = 0
            for e in evts:
                if e.get("event_type") == "auth_fail":
                    streak += 1
                    best = max(best, streak)
                else:
                    streak = 0
            max_streak = max(max_streak, best)
        return max_streak

    @staticmethod
    def _success_after_failure(events: list) -> int:
        per_ip_events = defaultdict(list)
        for e in events:
            per_ip_events[e.get("ip")].append(e)

        for ip, evts in per_ip_events.items():
            fail_run = 0
            for e in evts:
                if e.get("event_type") == "auth_fail":
                    fail_run += 1
                elif e.get("event_type") == "auth_success" and fail_run >= 3:
                    return 1
                else:
                    fail_run = 0
        return 0

    @staticmethod
    def _avg_time_between(events: list) -> float:
        timestamps = sorted(t for t in (_parse_ts(e) for e in events) if t is not None)
        if len(timestamps) < 2:
            return 0.0
        deltas = [
            (timestamps[i + 1] - timestamps[i]).total_seconds()
            for i in range(len(timestamps) - 1)
        ]
        return sum(deltas) / len(deltas) if deltas else 0.0