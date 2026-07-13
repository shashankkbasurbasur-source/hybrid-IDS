"""
HIDS Feature Schema
====================
Single source of truth for the HIDS production feature vector.

Every component that touches host-based features (the extractor, the
trainer, the predictor, and the manual-upload analyzer) MUST import
FEATURE_NAMES / FEATURE_VECTOR_LENGTH from here instead of hardcoding
a length or an index.

If you need to change the schema (add/remove a feature), change it
ONLY here, then retrain the model. Do not add a feature anywhere else
first.
"""

FEATURE_NAMES = [
    "failed_login_count",        # 0  total auth_fail events in window
    "success_login_count",       # 1  total auth_success events in window
    "unique_src_ips",            # 2  distinct source IPs seen
    "unique_usernames",          # 3  distinct usernames targeted
    "max_repeated_failures",     # 4  longest consecutive fail streak, single IP
    "success_after_failure",     # 5  1 if any IP succeeded after >=3 fails, else 0
    "avg_time_between_attempts", # 6  mean seconds between consecutive events
    "failed_login_rate",         # 7  fails / total events
    "root_login_attempts",       # 8  count of events targeting user 'root'
    "invalid_user_attempts",     # 9  count of "invalid user" events
    "ssh_session_count",         # 10 total events in window (proxy for sessions)
    "new_ip_count",              # 11 IPs not seen in prior window(s)
    "port_distinct_count",       # 12 distinct destination ports
    "auth_method_password",      # 13 count of password-based attempts
    "auth_method_pubkey",        # 14 count of publickey-based attempts
]

FEATURE_VECTOR_LENGTH = len(FEATURE_NAMES)


def empty_vector() -> list:
    return [0.0] * FEATURE_VECTOR_LENGTH


def vector_to_dict(vector: list) -> dict:
    if len(vector) != FEATURE_VECTOR_LENGTH:
        raise ValueError(
            f"Expected feature vector of length {FEATURE_VECTOR_LENGTH}, got {len(vector)}"
        )
    return dict(zip(FEATURE_NAMES, vector))


def validate_vector(vector: list) -> None:
    if not isinstance(vector, list):
        raise ValueError("Feature vector must be a list")
    if len(vector) != FEATURE_VECTOR_LENGTH:
        raise ValueError(
            f"HIDS feature vector must have exactly {FEATURE_VECTOR_LENGTH} "
            f"values (schema: {FEATURE_NAMES}), got {len(vector)}"
        )