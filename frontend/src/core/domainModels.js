import { normalizeAlertEnrichment, normalizeAlertIocs } from "./alertEnrichment.js";
import { normalizeAlertDisposition, normalizeAlertLifecycle } from "./alertLifecycle.js";
import { parseActionEntry } from "./actionSystem.js";
import { normalizeCaseTimelineEvent } from "./caseTimeline.js";

function safeString(value) {
  return String(value ?? "").trim();
}

function safeNumber(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}

function safeCaseClosureReason(value) {
  const normalized = safeString(value).toLowerCase();
  return normalized || "";
}

export function normalizeAlertModel(alert = {}) {
  const enrichment = normalizeAlertEnrichment(alert);
  const iocs = normalizeAlertIocs(alert);
  const lifecycle = normalizeAlertLifecycle(alert);
  const disposition = normalizeAlertDisposition(alert);
  return {
    ...alert,
    id: safeString(alert.id || alert.alert_id),
    lifecycle,
    disposition,
    status: lifecycle,
    enrichment,
    iocs,
    watchlistHit: Boolean(alert.watchlistHit ?? alert.watchlist_hit),
    watchlistHitsCount: safeNumber(alert.watchlistHitsCount ?? alert.watchlist_hits_count) ?? 0,
    watchlistMatches: Array.isArray(alert.watchlistMatches || alert.watchlist_matches)
      ? (alert.watchlistMatches || alert.watchlist_matches)
      : [],
    sourceIp: alert.sourceIp || alert.source_ip || enrichment.ip || "",
    attackType: alert.attackType || alert.attack_type || enrichment.attackType || "",
    severity: safeString(alert.severity || enrichment.severity || "medium").toLowerCase(),
    caseId: safeString(alert.caseId || alert.case_id),
    investigationId: safeString(alert.investigationId || alert.investigation_id),
    assignedTo: safeString(alert.assignedTo || alert.assigned_to || alert.analyst),
    mergedIntoCaseId: safeString(alert.mergedIntoCaseId || alert.merged_into_case_id || alert.caseId || alert.case_id),
    updatedAt: alert.updatedAt || alert.updated_at || null,
    createdAt: alert.createdAt || alert.created_at || null,
    acknowledgedAt: alert.acknowledgedAt || alert.acknowledged_at || null,
    closedAt: alert.closedAt || alert.closed_at || null,
    timeToAck: safeNumber(alert.timeToAck ?? alert.time_to_ack),
    timeToClose: safeNumber(alert.timeToClose ?? alert.time_to_close),
    overdue: Boolean(alert.overdue),
    urgencyScore: safeNumber(alert.urgencyScore ?? alert.urgency_score) ?? 0,
    slaThresholds: alert.slaThresholds || alert.sla_thresholds || null,
    slaBreaches: alert.slaBreaches || alert.sla_breaches || null,
    hasCase: Boolean(alert.hasCase || alert.caseId || alert.case_id),
    isBlocked: Boolean(alert.isBlocked || alert.is_blocked),
    entityContext: alert.entityContext || alert.entity_context || alert.details?.entity_context || {},
  };
}

export function normalizeActionEventModel(entry = {}) {
  return parseActionEntry(entry) || null;
}

export function normalizeCaseModel(caseRecord = {}) {
  const sourceAlertId = safeString(caseRecord.source_alert_id || caseRecord.alert_id || caseRecord.alert?.id);
  const sourceInvestigationId = safeString(caseRecord.source_investigation_id || caseRecord.investigation_id || caseRecord.investigation?.id);
  return {
    ...caseRecord,
    id: safeString(caseRecord.id),
    status: safeString(caseRecord.status || "open").toLowerCase() || "open",
    closureReason: safeCaseClosureReason(caseRecord.closureReason || caseRecord.closure_reason),
    closedAt: caseRecord.closedAt || caseRecord.closed_at || null,
    sourceAlertId,
    sourceInvestigationId,
    parentCaseId: safeString(caseRecord.parent_case_id),
    linkedAlertIds: Array.isArray(caseRecord.linked_alert_ids) ? caseRecord.linked_alert_ids.map(value => safeString(value)).filter(Boolean) : [],
    linkedCases: Array.isArray(caseRecord.linked_cases) ? caseRecord.linked_cases.map(value => safeString(value)).filter(Boolean) : [],
    actions: (Array.isArray(caseRecord.actions) ? caseRecord.actions : []).map(normalizeActionEventModel).filter(Boolean),
    timeline: (Array.isArray(caseRecord.timeline) ? caseRecord.timeline : []).map(normalizeCaseTimelineEvent).filter(Boolean)
  };
}

export function normalizeEnrichmentRecord(source = {}) {
  return normalizeAlertEnrichment(source);
}

export function normalizeCaseQueueModel({ queue = [], activeCaseId = null } = {}) {
  return {
    queue: Array.isArray(queue) ? queue.map(value => safeString(value)).filter(Boolean) : [],
    activeCaseId: activeCaseId ? safeString(activeCaseId) : null
  };
}
