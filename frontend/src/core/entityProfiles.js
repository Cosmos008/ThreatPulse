import { normalizeAlertEnrichment } from "./alertEnrichment.js";

const severityWeight = {
  low: 20,
  medium: 45,
  high: 70,
  critical: 90
};

const criticalityWeight = {
  low: 0,
  medium: 10,
  high: 25
};

function safeString(value) {
  return String(value || "").trim();
}

function normalizeCriticality(value) {
  const normalized = safeString(value).toLowerCase();
  if (normalized === "low" || normalized === "medium" || normalized === "high") {
    return normalized;
  }
  return "medium";
}

function normalizeTimestamp(value) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? Date.now() : parsed;
}

export function extractAlertEntities(alert = {}) {
  const enrichment = normalizeAlertEnrichment(alert);
  const context = alert.entityContext || alert.entity_context || {};
  const entities = [];

  if (safeString(enrichment.ip)) {
    entities.push({
      type: "ip",
      value: enrichment.ip,
      assetCriticality: normalizeCriticality(context.ip?.asset_criticality || context.ip?.assetCriticality || alert.details?.asset_criticality)
    });
  }
  if (safeString(enrichment.username || enrichment.account || enrichment.email)) {
    entities.push({
      type: "user",
      value: enrichment.username || enrichment.account || enrichment.email,
      assetCriticality: normalizeCriticality(context.user?.asset_criticality || context.user?.assetCriticality || alert.details?.asset_criticality)
    });
  }
  if (safeString(enrichment.hostname || enrichment.device)) {
    entities.push({
      type: "host",
      value: enrichment.hostname || enrichment.device,
      assetCriticality: normalizeCriticality(context.host?.asset_criticality || context.host?.assetCriticality || alert.details?.asset_criticality)
    });
  }
  return entities;
}

function summarizeAlert(alert) {
  return {
    id: safeString(alert.id || alert.raw?.id),
    rule: safeString(alert.attackType || alert.attack_type || alert.rule || "alert"),
    severity: safeString(alert.severity || "medium").toLowerCase(),
    risk_score: Number(alert.riskScore ?? alert.risk_score ?? alert.details?.risk_score ?? 0) || 0,
    timestamp: normalizeTimestamp(alert.timestamp || alert.createdAt || alert.created_at)
  };
}

export function buildEntityProfile(entity, alerts = [], baseProfile = null) {
  const matchingAlerts = alerts
    .filter(alert => extractAlertEntities(alert).some(candidate =>
      candidate.type === entity.type && safeString(candidate.value).toLowerCase() === safeString(entity.value).toLowerCase()
    ))
    .sort((left, right) => normalizeTimestamp(left.timestamp || left.createdAt || left.created_at) - normalizeTimestamp(right.timestamp || right.createdAt || right.created_at));

  const recentAlerts = matchingAlerts.slice(-5).reverse().map(summarizeAlert);
  const attackTypes = [...new Set(matchingAlerts.map(alert => safeString(alert.attackType || alert.attack_type || alert.rule)).filter(Boolean))];
  const totalRisk = matchingAlerts.reduce((highest, alert) => {
    const score = Number(alert.riskScore ?? alert.risk_score ?? alert.details?.risk_score ?? severityWeight[String(alert.severity || "medium").toLowerCase()] ?? 0) || 0;
    return Math.max(highest, score);
  }, 0);
  const assetCriticality = normalizeCriticality(entity.assetCriticality || baseProfile?.asset_criticality || baseProfile?.assetCriticality);
  const riskScore = Math.min(100, totalRisk + Math.max(0, matchingAlerts.length - 1) * 4 + criticalityWeight[assetCriticality]);
  const firstSeen = matchingAlerts[0] ? new Date(normalizeTimestamp(matchingAlerts[0].timestamp || matchingAlerts[0].createdAt || matchingAlerts[0].created_at)).toISOString() : baseProfile?.first_seen || null;
  const lastSeen = matchingAlerts.at(-1) ? new Date(normalizeTimestamp(matchingAlerts.at(-1).timestamp || matchingAlerts.at(-1).createdAt || matchingAlerts.at(-1).created_at)).toISOString() : baseProfile?.last_seen || null;
  const severityBreakdown = matchingAlerts.reduce((bucket, alert) => {
    const severity = safeString(alert.severity || "medium").toLowerCase();
    bucket[severity] = (bucket[severity] || 0) + 1;
    return bucket;
  }, {});

  return {
    entity_type: entity.type,
    entity_key: entity.value,
    display_name: entity.value,
    first_seen: firstSeen,
    last_seen: lastSeen,
    alert_count: matchingAlerts.length || baseProfile?.alert_count || 0,
    case_count: baseProfile?.case_count || 0,
    related_attack_types: attackTypes.length ? attackTypes : (baseProfile?.related_attack_types || []),
    risk_score: riskScore || baseProfile?.risk_score || 0,
    asset_criticality: assetCriticality,
    enrichment: baseProfile?.enrichment || {},
    activity_summary: {
      total_alerts: matchingAlerts.length,
      severity_breakdown: severityBreakdown,
      top_attack_types: attackTypes.slice(0, 3)
    },
    recent_alerts: recentAlerts.length ? recentAlerts : (baseProfile?.recent_alerts || [])
  };
}

export function buildEntityContextForAlert(alert, alerts = []) {
  const context = alert?.entityContext || alert?.entity_context || {};
  return extractAlertEntities(alert).reduce((profiles, entity) => {
    const baseProfile = context[entity.type] || null;
    profiles[entity.type] = buildEntityProfile(entity, alerts, baseProfile);
    return profiles;
  }, {});
}
