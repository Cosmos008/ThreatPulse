MITRE_MAP = {
    "credential_stuffing": {
        "technique": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access"
    },
    "honeypot_access": {
        "technique": "T1078",
        "name": "Valid Accounts",
        "tactic": "Persistence"
    },
    "rate_limit_abuse": {
        "technique": "T1499",
        "name": "Endpoint Denial of Service",
        "tactic": "Impact"
    },
    "high_risk_actor": {
        "technique": "T1589",
        "name": "Gather Victim Identity Information",
        "tactic": "Reconnaissance"
    },
    "anomaly_spike": {
        "technique": "T1036",
        "name": "Masquerading",
        "tactic": "Defense Evasion"
    },
    "device_abuse": {
        "technique": "T1204",
        "name": "User Execution",
        "tactic": "Execution"
    }
}


def classify_threat(risk_score):
    if risk_score >= 150:
        return "Critical"
    if risk_score >= 100:
        return "High"
    if risk_score >= 50:
        return "Medium"
    return "Low"
