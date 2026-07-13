"""
Synthetic Auth-Log Window Generator (Rule Distillation)
==========================================================
No labeled real-world auth-log dataset exists yet (ADFA-LD is the
wrong feature space). This generates synthetic windows spanning
normal behavior and several attack patterns, labeled via the same
thresholds as the rule engine. It's a bootstrap, not a replacement for
real data — swap out for a real labeled dataset later without
touching trainer.py, which only depends on (events, label) pairs.
"""

import random
from datetime import datetime, timedelta

_USERS = ["root", "admin", "ubuntu", "test", "guest", "oracle", "backup",
          "finance", "hr", "postgres", "www-data", "deploy"]

_PLACEHOLDER_YEAR = 2000


def _ts_str(dt: datetime) -> str:
    return dt.strftime("%b %d %H:%M:%S").replace(" 0", " ")


def _make_event(dt, event_type, user, ip, port=22, method="password", invalid=False):
    return {
        "timestamp": _ts_str(dt),
        "source": "ssh",
        "event_type": event_type,
        "user": user,
        "ip": ip,
        "port": port,
        "auth_method": method,
        "invalid_user": invalid,
        "raw": f"synthetic {event_type} for {user} from {ip} port {port}",
    }


def _random_ip(rng):
    return f"192.168.1.{rng.randint(2, 254)}"


def generate_normal_window(rng: random.Random):
    start = datetime(_PLACEHOLDER_YEAR, 5, 10, 9, 0, 0)
    events = []
    num_events = rng.randint(1, 4)
    ip = _random_ip(rng)
    user = rng.choice(_USERS)
    t = start
    for _ in range(num_events):
        t += timedelta(seconds=rng.randint(30, 600))
        if rng.random() < 0.15:
            events.append(_make_event(t, "auth_fail", user, ip))
            t += timedelta(seconds=rng.randint(2, 10))
        events.append(_make_event(t, "auth_success", user, ip))
    return events


def generate_brute_force_window(rng: random.Random):
    start = datetime(_PLACEHOLDER_YEAR, 5, 10, 11, 0, 0)
    ip = _random_ip(rng)
    user = rng.choice(_USERS)
    num_fails = rng.randint(6, 40)
    events = []
    t = start
    for _ in range(num_fails):
        t += timedelta(seconds=rng.randint(1, 6))
        events.append(_make_event(t, "auth_fail", user, ip))
    if rng.random() < 0.3:
        t += timedelta(seconds=rng.randint(1, 6))
        events.append(_make_event(t, "auth_success", user, ip))
    return events


def generate_credential_stuffing_window(rng: random.Random):
    start = datetime(_PLACEHOLDER_YEAR, 5, 10, 12, 0, 0)
    ip = _random_ip(rng)
    events = []
    t = start
    num_users = rng.randint(6, 15)
    for _ in range(num_users):
        user = rng.choice(_USERS)
        t += timedelta(seconds=rng.randint(1, 5))
        events.append(_make_event(t, "auth_fail", user, ip, invalid=rng.random() < 0.4))
    return events


def generate_password_spray_window(rng: random.Random):
    start = datetime(_PLACEHOLDER_YEAR, 5, 10, 13, 0, 0)
    events = []
    t = start
    num_attempts = rng.randint(8, 20)
    for _ in range(num_attempts):
        ip = _random_ip(rng)
        user = rng.choice(_USERS)
        t += timedelta(seconds=rng.randint(5, 30))
        events.append(_make_event(t, "auth_fail", user, ip))
    return events


def generate_recon_window(rng: random.Random):
    start = datetime(_PLACEHOLDER_YEAR, 5, 10, 14, 0, 0)
    ip = _random_ip(rng)
    events = []
    t = start
    num_attempts = rng.randint(3, 8)
    for _ in range(num_attempts):
        user = f"probe{rng.randint(1, 999)}"
        t += timedelta(seconds=rng.randint(10, 60))
        events.append(_make_event(t, "auth_fail", user, ip, invalid=True))
    return events


def generate_privilege_escalation_window(rng: random.Random):
    start = datetime(_PLACEHOLDER_YEAR, 5, 10, 15, 0, 0)
    ip = _random_ip(rng)
    events = []
    t = start
    num_fails = rng.randint(3, 10)
    for _ in range(num_fails):
        t += timedelta(seconds=rng.randint(1, 8))
        events.append(_make_event(t, "auth_fail", "root", ip))
    t += timedelta(seconds=rng.randint(1, 8))
    events.append(_make_event(t, "auth_success", "root", ip))
    return events


_GENERATORS = [
    (generate_normal_window, 0, 0.45),
    (generate_brute_force_window, 1, 0.15),
    (generate_credential_stuffing_window, 1, 0.12),
    (generate_password_spray_window, 1, 0.12),
    (generate_recon_window, 1, 0.08),
    (generate_privilege_escalation_window, 1, 0.08),
]


def generate_dataset(n_windows: int = 4000, seed: int = 42):
    rng = random.Random(seed)
    generators, labels, weights = zip(*_GENERATORS)

    dataset = []
    for _ in range(n_windows):
        gen, label = rng.choices(list(zip(generators, labels)), weights=weights, k=1)[0]
        events = gen(rng)
        dataset.append((events, label))
    return dataset