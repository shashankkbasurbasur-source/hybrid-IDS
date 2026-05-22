from collections import defaultdict


class LogFeatureExtractor:
    """
    Converts parsed log events into feature vector for HIDS model
    """

    def extract(self, events):
        features = [0] * 100  # match your model input

        if not events:
            return features

        ip_events = defaultdict(list)

        for e in events:
            ip_events[e["ip"]].append(e)

        total_fail = 0
        total_success = 0
        total_ips = len(ip_events)
        total_users = set()
        success_after_fail = 0
        max_fail_per_ip = 0

        for ip, evts in ip_events.items():

            if len(evts) < 3:
                continue

            fail_count = sum(1 for e in evts if e["event_type"] == "auth_fail")
            success_count = sum(1 for e in evts if e["event_type"] == "auth_success")

            users = set(e["user"] for e in evts)

            if success_count > 0 and fail_count >= 3:
                success_after_fail += 1

            total_fail += fail_count
            total_success += success_count
            total_users.update(users)

            if fail_count > max_fail_per_ip:
                max_fail_per_ip = fail_count

        total_events = len(events)

        # --- Core behavioral features ---
        features[0] = total_fail
        features[1] = total_success
        features[2] = total_ips
        features[3] = len(total_users)
        features[4] = success_after_fail

        # --- Advanced behavioral signals ---
        features[5] = total_fail / (total_success + 1)
        features[6] = max_fail_per_ip
        features[7] = total_events / (total_ips + 1)

        return features