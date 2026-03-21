BLOCKED_IPS = set()


def block_ip(ip: str):
    if ip:
        BLOCKED_IPS.add(ip)


def is_blocked(ip: str) -> bool:
    return ip in BLOCKED_IPS
