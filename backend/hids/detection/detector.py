import time
from collections import deque

from backend.hids.features.feature_extractor import AuthLogFeatureExtractor
from backend.hids.features.feature_schema import vector_to_dict
from backend.hids.features.window_manager import SlidingWindowManager
from backend.hids.ml.predictor import predict_host
from backend.hids.detection.threat_classifier import classify, severity_for, ATTACK_NORMAL
from backend.hids.detection.mitre_mapper import map_attack
from backend.hids.detection.host_correlator import correlate
from backend.hids.alerts.alert_manager import build_and_dispatch_alert


class HIDSDetector:
    def __init__(self, window_seconds=300, min_events_to_score=2,
                 min_syscalls_to_score=20, decision_threshold=0.5,
                 alert_cooldown_seconds=120, model_base_path="models"):
        self.window_seconds = window_seconds
        self.min_events_to_score = min_events_to_score
        self.min_syscalls_to_score = min_syscalls_to_score
        self.decision_threshold = decision_threshold
        self.alert_cooldown_seconds = alert_cooldown_seconds
        self.model_base_path = model_base_path

        self.extractor = AuthLogFeatureExtractor()
        self._auth_windows = SlidingWindowManager(window_seconds=window_seconds)
        self._auth_seen_ips = set()
        self._last_alert_at = {}
        self._syscall_window = deque()

    def _prune_syscall_window(self, now):
        while self._syscall_window and now - self._syscall_window[0][0] > self.window_seconds:
            self._syscall_window.popleft()

    def process_syscall_event(self, event):
        now = time.monotonic()

        self._syscall_window.append((now, event))

        self._prune_syscall_window(now)

        window = [e for _, e in self._syscall_window]

        if len(window) < self.min_syscalls_to_score:
            return None

        from backend.hids.ml.syscall_predictor import predict_syscall

        syscall_ids = [e["syscall_num"] for e in window]

        try:
            return predict_syscall(
                syscall_ids,
                base_path=self.model_base_path,
            )
        except RuntimeError:
            return None

    def _current_syscall_window_events(self):
        return [e for _, e in self._syscall_window]

    def process_live_auth_event(self, event, syscall_score=None):
        ip = event.get("ip")
        if not ip:
            return None

        window_events = self._auth_windows.ingest(ip, event)
        if len(window_events) < self.min_events_to_score:
            return None

        seen_before = self._auth_seen_ips - {ip}
        vector = self.extractor.extract(window_events, seen_ips_before=seen_before)
        self._auth_seen_ips.add(ip)

        auth_score = predict_host(vector, base_path=self.model_base_path)
        unified_score = correlate(auth_score, syscall_score)

        syscall_events = self._current_syscall_window_events() if syscall_score is not None else None
        attack_type = classify(vector, unified_score, self.decision_threshold, syscall_events=syscall_events)

        if attack_type == ATTACK_NORMAL:
            return None

        now = time.monotonic()
        last = self._last_alert_at.get(ip)
        if last is not None and (now - last) < self.alert_cooldown_seconds:
            return None

        mitre = map_attack(attack_type)
        severity = severity_for(unified_score)

        alert = build_and_dispatch_alert(
            source_ip=ip, probability=unified_score, attack_type=attack_type,
            severity=severity, mitre=mitre, feature_vector=vector,
            auth_score=auth_score, syscall_score=syscall_score,
        )
        self._last_alert_at[ip] = now
        return alert

    def run_live(self, auth_source, syscall_source=None):
        import threading
        latest_syscall_score = {"value": None}

        def syscall_loop():
            for event in syscall_source.events():
                score = self.process_syscall_event(event)
                if score is not None:
                    latest_syscall_score["value"] = score

        if syscall_source is not None:
            threading.Thread(target=syscall_loop, daemon=True).start()
            print("[HIDS Detector] Syscall branch (auditd) monitoring started")
        else:
            print("[HIDS Detector] Syscall branch disabled — running on auth branch alone")

        print(f"[HIDS Detector] Auth branch monitoring started "
              f"(window={self.window_seconds}s, cooldown={self.alert_cooldown_seconds}s)")

        for event in auth_source.events():
            alert = self.process_live_auth_event(event, latest_syscall_score["value"])
            if alert:
                print(f"[HIDS Detector] ALERT: {alert['attack_type']} from {alert['source_ip']} "
                      f"(unified={alert['confidence']:.2f}, auth={alert['auth_score']}, "
                      f"syscall={alert['syscall_score']}, MITRE {alert['mitre_technique']})")

    def analyze(self, log_source, persist_to_incidents=False):
        """Manual/forensic path — AUTH BRANCH ONLY, unchanged from before."""
        window_manager = SlidingWindowManager(window_seconds=None)
        seen_ips = set()
        results_by_ip = {}
        total_events = 0

        for event in log_source.events():
            ip = event.get("ip")
            if not ip:
                continue
            total_events += 1

            window_events = window_manager.ingest(ip, event)
            seen_before = seen_ips - {ip}
            vector = self.extractor.extract(window_events, seen_ips_before=seen_before)
            seen_ips.add(ip)

            probability = predict_host(vector, base_path=self.model_base_path)
            attack_type = classify(vector, probability, self.decision_threshold)
            mitre = map_attack(attack_type)
            severity = severity_for(probability) if attack_type != ATTACK_NORMAL else "LOW"

            results_by_ip[ip] = {
                "source_ip": ip, "event_count": len(window_events), "attack_type": attack_type,
                "severity": severity, "confidence": round(float(probability), 4),
                "mitre_technique": mitre.get("technique"), "mitre_tactic": mitre.get("tactic"),
                "features": vector_to_dict(vector),
            }

        findings = sorted(results_by_ip.values(), key=lambda r: r["confidence"], reverse=True)

        if persist_to_incidents:
            for finding in findings:
                if finding["attack_type"] != ATTACK_NORMAL:
                    mitre = {"technique": finding["mitre_technique"], "tactic": finding["mitre_tactic"]}
                    build_and_dispatch_alert(
                        source_ip=finding["source_ip"], probability=finding["confidence"],
                        attack_type=finding["attack_type"], severity=finding["severity"],
                        mitre=mitre, feature_vector=list(finding["features"].values()),
                        auth_score=finding["confidence"], syscall_score=None,
                    )

        return {
            "total_events_parsed": total_events, "unique_source_ips": len(results_by_ip),
            "findings": findings, "flagged_count": sum(1 for f in findings if f["attack_type"] != ATTACK_NORMAL),
            "imported_to_incidents": persist_to_incidents,
        }