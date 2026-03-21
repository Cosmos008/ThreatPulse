from services.investigation_api.models import get_all_alerts
from shared.neo4j_utils import get_driver


def _fallback_relationships(entity_type: str, value: str) -> dict:
    alerts = get_all_alerts()
    related_accounts = set()
    related_ips = set()
    related_devices = set()

    for alert in alerts:
        details = alert.get("details") or {}
        ip = details.get("ip") or alert.get("ip")
        user_id = details.get("user_id")
        device_hash = details.get("device_hash") or details.get("device_id")

        if entity_type == "ip" and ip == value:
            if user_id:
                related_accounts.add(user_id)
            if device_hash:
                related_devices.add(device_hash)
        if entity_type == "account" and user_id == value:
            if ip:
                related_ips.add(ip)
            if device_hash:
                related_devices.add(device_hash)
        if entity_type == "device" and device_hash == value:
            if ip:
                related_ips.add(ip)
            if user_id:
                related_accounts.add(user_id)

    return {
        "entity_type": entity_type,
        "value": value,
        "related_ips": sorted(related_ips),
        "related_accounts": sorted(related_accounts),
        "related_devices": sorted(related_devices),
        "source": "fallback",
    }


def investigate_ip(ip: str) -> dict:
    try:
        driver = get_driver()
        with driver.session() as session:
            record = session.run(
                """
                MATCH (ip:IP {value: $value})
                OPTIONAL MATCH (ip)-[:TARGETS]->(account:Account)
                OPTIONAL MATCH (ip)<-[:SEEN_FROM]-(device:Device)
                RETURN collect(DISTINCT account.value) AS accounts,
                       collect(DISTINCT device.value) AS devices
                """,
                value=ip,
            ).single()
        driver.close()
        result = {
            "entity_type": "ip",
            "value": ip,
            "related_accounts": sorted([value for value in (record["accounts"] or []) if value]),
            "related_devices": sorted([value for value in (record["devices"] or []) if value]),
            "source": "neo4j",
        }
        if not result["related_accounts"] and not result["related_devices"]:
            return _fallback_relationships("ip", ip)
        return result
    except Exception:
        return _fallback_relationships("ip", ip)


def investigate_account(account_id: str) -> dict:
    try:
        driver = get_driver()
        with driver.session() as session:
            record = session.run(
                """
                MATCH (account:Account {value: $value})
                OPTIONAL MATCH (ip:IP)-[:TARGETS]->(account)
                OPTIONAL MATCH (account)-[:USES]->(device:Device)
                RETURN collect(DISTINCT ip.value) AS ips,
                       collect(DISTINCT device.value) AS devices
                """,
                value=account_id,
            ).single()
        driver.close()
        result = {
            "entity_type": "account",
            "value": account_id,
            "related_ips": sorted([value for value in (record["ips"] or []) if value]),
            "related_devices": sorted([value for value in (record["devices"] or []) if value]),
            "source": "neo4j",
        }
        if not result["related_ips"] and not result["related_devices"]:
            return _fallback_relationships("account", account_id)
        return result
    except Exception:
        return _fallback_relationships("account", account_id)


def investigate_device(device_hash: str) -> dict:
    try:
        driver = get_driver()
        with driver.session() as session:
            record = session.run(
                """
                MATCH (device:Device {value: $value})
                OPTIONAL MATCH (account:Account)-[:USES]->(device)
                OPTIONAL MATCH (device)-[:SEEN_FROM]->(ip:IP)
                RETURN collect(DISTINCT account.value) AS accounts,
                       collect(DISTINCT ip.value) AS ips
                """,
                value=device_hash,
            ).single()
        driver.close()
        result = {
            "entity_type": "device",
            "value": device_hash,
            "related_accounts": sorted([value for value in (record["accounts"] or []) if value]),
            "related_ips": sorted([value for value in (record["ips"] or []) if value]),
            "source": "neo4j",
        }
        if not result["related_accounts"] and not result["related_ips"]:
            return _fallback_relationships("device", device_hash)
        return result
    except Exception:
        return _fallback_relationships("device", device_hash)
