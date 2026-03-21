from shared.config import get_honeypot_file


def load_honeypots():
    honeypot_file = get_honeypot_file()

    with honeypot_file.open(encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}


honeypot_accounts = load_honeypots()


def check_honeypot(event):

    user = event.get("user_id")

    if user in honeypot_accounts:

        return {
            "rule": "honeypot_access",
            "severity": "critical",
            "ip": event.get("ip"),
            "user_id": user,
            "explanation": [
                "Matched honeypot account",
                "High confidence threat",
                "Unauthorized login attempt"
            ]
        }

    return None
