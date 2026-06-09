# backend/features/log_features.py

from collections import defaultdict


class LogFeatureExtractor:
    """
    Converts parsed SSH log events into feature vectors for HIDS model.
    """

    def extract(self, events: list) -> list:
        """
        Aggregate 100-dim feature vector for the entire event window.
        Used by host_model.predict_host().
        """
        features = [0.0] * 100

        if not events:
            return features

        ip_events = defaultdict(list)
        for e in events:
            ip_events[e["ip"]].append(e)

        total_fail         = 0
        total_success      = 0
        total_ips          = len(ip_events)
        total_users        = set()
        success_after_fail = 0
        max_fail_per_ip    = 0

        for ip, evts in ip_events.items():
            fail_count    = sum(1 for e in evts if e["event_type"] == "auth_fail")
            success_count = sum(1 for e in evts if e["event_type"] == "auth_success")
            users         = {e["user"] for e in evts}

            if success_count > 0 and fail_count >= 3:
                success_after_fail += 1

            total_fail    += fail_count
            total_success += success_count
            total_users.update(users)

            if fail_count > max_fail_per_ip:
                max_fail_per_ip = fail_count

        total_events = len(events)

        features[0] = float(total_fail)
        features[1] = float(total_success)
        features[2] = float(total_ips)
        features[3] = float(len(total_users))
        features[4] = float(success_after_fail)
        features[5] = total_fail / (total_success + 1)
        features[6] = float(max_fail_per_ip)
        features[7] = total_events / (total_ips + 1)

        return features

    def extract_per_ip(self, events: list) -> list:
        """
        Returns one feature dict per unique source IP.
        Used by SSHRuleDetector.detect().
        """
        if not events:
            return []

        ip_events = defaultdict(list)
        for e in events:
            ip_events[e["ip"]].append(e)

        rows = []
        for ip, evts in ip_events.items():
            fail_count    = sum(1 for e in evts if e["event_type"] == "auth_fail")
            success_count = sum(1 for e in evts if e["event_type"] == "auth_success")
            users         = {e["user"] for e in evts}

            rows.append({
                "ip"               : ip,
                "fail_count"       : fail_count,
                "success_count"    : success_count,
                "unique_users"     : len(users),
                "success_after_fail": 1 if (success_count > 0 and fail_count >= 3) else 0,
                "label"            : "attack" if fail_count >= 3 else "normal",
            })

        return rows