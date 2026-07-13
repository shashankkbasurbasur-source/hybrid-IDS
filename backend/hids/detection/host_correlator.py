AUTH_WEIGHT = 0.5
SYSCALL_WEIGHT = 0.5


def correlate(auth_score, syscall_score, auth_weight: float = AUTH_WEIGHT, syscall_weight: float = SYSCALL_WEIGHT) -> float:
    if auth_score is None and syscall_score is None:
        return 0.0
    if auth_score is None:
        return round(float(syscall_score), 4)
    if syscall_score is None:
        return round(float(auth_score), 4)
    total_weight = auth_weight + syscall_weight
    return round((auth_score * auth_weight + syscall_score * syscall_weight) / total_weight, 4)