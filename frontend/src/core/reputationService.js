export function getIpReputation(alert = {}) {
  const threatLevel = String(alert.threatLevel || alert.threat_level || "").toLowerCase();
  const riskScore = Number(alert.riskScore ?? alert.risk_score ?? 0) || 0;
  const blocked = Boolean(alert.isBlocked || alert.is_blocked);

  if (blocked || threatLevel === "high" || riskScore >= 90) {
    return "malicious";
  }
  if (threatLevel === "medium" || riskScore >= 60) {
    return "suspicious";
  }
  if (threatLevel === "low" || riskScore > 0) {
    return "low risk";
  }
  return "unknown";
}
