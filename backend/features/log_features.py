from collections import defaultdict

class LogFeatureExtractor:
    """
    Extracts behavioral features from normalized log events.
    """

    def extract(self, events):
        ip_events = defaultdict(list)

        # Group events by IP
        for e in events:
            ip_events[e["ip"]].append(e)

        feature_rows = []

        for ip, evts in ip_events.items():

            # -----------------------------
            # SAFETY FILTER (VERY IMPORTANT)
            # -----------------------------
            # Skip IPs with too few events (noise)
            if len(evts) < 3:
                continue

            fail_count = sum(1 for e in evts if e["event_type"] == "auth_fail")
            success_count = sum(1 for e in evts if e["event_type"] == "auth_success")

            users = set(e["user"] for e in evts)

            success_after_fail = 1 if (success_count > 0 and fail_count >= 3) else 0

            # -----------------------------
            # REALISTIC LABELING LOGIC
            # -----------------------------
# Ground-truth labeling (conservative)
            if fail_count >= 15 and success_after_fail == 1:
                label = "attack"
            else:
                label = "normal"


            feature_rows.append({
                "ip": ip,
                "fail_count": fail_count,
                "unique_users": len(users),
                "success_after_fail": success_after_fail,
                "label": label
            })

        return feature_rows

