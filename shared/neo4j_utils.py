from shared.config import get_neo4j_config


def get_driver():
    from neo4j import GraphDatabase

    config = get_neo4j_config()
    return GraphDatabase.driver(
        config["uri"],
        auth=(config["user"], config["password"]),
    )


def sync_relationships(event: dict):
    ip = event.get("ip")
    user_id = event.get("user_id")
    device_hash = event.get("device_hash") or event.get("device_id")

    if not ip and not user_id and not device_hash:
        return

    driver = get_driver()
    query_parts = []
    if ip:
        query_parts.append("MERGE (ip:IP {value: $ip}) SET ip.last_seen = datetime()")
    if user_id:
        query_parts.append("MERGE (account:Account {value: $user_id}) SET account.last_seen = datetime()")
    if device_hash:
        query_parts.append("MERGE (device:Device {value: $device_hash}) SET device.last_seen = datetime()")
    if ip and user_id:
        query_parts.append("MERGE (ip)-[:TARGETS]->(account)")
    if user_id and device_hash:
        query_parts.append("MERGE (account)-[:USES]->(device)")
    if device_hash and ip:
        query_parts.append("MERGE (device)-[:SEEN_FROM]->(ip)")

    query = "\n".join(query_parts)
    with driver.session() as session:
        session.run(query, ip=ip, user_id=user_id, device_hash=device_hash)
    driver.close()
