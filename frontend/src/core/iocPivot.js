import { normalizeAlertIocs } from "./alertEnrichment.js";

const IOC_TYPE_LABELS = {
  ip: "IP",
  domain: "Domain",
  email: "Email",
  username: "Username",
  hostname: "Hostname",
  hash: "Hash"
};

const IOC_BUCKET_BY_TYPE = {
  ip: "ips",
  domain: "domains",
  email: "emails",
  username: "usernames",
  hostname: "hostnames",
  hash: "hashes"
};

function safeString(value) {
  return String(value ?? "").trim();
}

export function normalizeIocType(iocType) {
  const normalized = safeString(iocType).toLowerCase();
  if (normalized in IOC_BUCKET_BY_TYPE) {
    return normalized;
  }
  if (normalized.endsWith("es")) {
    const singular = normalized.slice(0, -2);
    if (singular in IOC_BUCKET_BY_TYPE) {
      return singular;
    }
  }
  if (normalized.endsWith("s")) {
    const singular = normalized.slice(0, -1);
    if (singular in IOC_BUCKET_BY_TYPE) {
      return singular;
    }
  }
  return normalized;
}

export function getIocLabel(iocType) {
  return IOC_TYPE_LABELS[normalizeIocType(iocType)] || "IOC";
}

export function normalizeIocValue(iocType, value) {
  const normalizedType = normalizeIocType(iocType);
  const text = safeString(value);
  if (normalizedType === "domain" || normalizedType === "email" || normalizedType === "username" || normalizedType === "hostname") {
    return text.toLowerCase();
  }
  if (normalizedType === "hash") {
    return text.toLowerCase();
  }
  return text;
}

export function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function buildIocPivotTriggerMarkup(iocType, value, options = {}) {
  const rawValue = safeString(value);
  const normalizedType = normalizeIocType(iocType);
  const normalizedValue = normalizeIocValue(normalizedType, rawValue);
  if (!rawValue || !normalizedType || !normalizedValue) {
    return options.fallback ?? escapeHtml(rawValue);
  }
  const className = options.className || "ioc-link";
  const attrs = options.attrs || "";
  return `<button type="button" class="${escapeHtml(className)}" data-ioc-pivot-type="${escapeHtml(normalizedType)}" data-ioc-pivot-value="${escapeHtml(rawValue)}" ${attrs}>${escapeHtml(rawValue)}</button>`;
}

export function buildIocEntriesForAlert(alert) {
  const iocs = normalizeAlertIocs(alert);
  return Object.entries(iocs).flatMap(([bucket, values]) => {
    const normalizedType = normalizeIocType(bucket);
    return (Array.isArray(values) ? values : [])
      .map(value => safeString(value))
      .filter(Boolean)
      .map(value => ({
        type: normalizedType,
        value,
        normalizedValue: normalizeIocValue(normalizedType, value)
      }));
  });
}

function buildActivityHaystack(entry) {
  return [
    entry?.actionType,
    entry?.action,
    entry?.message,
    entry?.targetId,
    entry?.target_id,
    entry?.relatedAlertId,
    entry?.related_alert_id,
    entry?.relatedCaseId,
    entry?.related_case_id,
    entry?.details
  ].map(value => safeString(value).toLowerCase()).join("\n");
}

function matchesCaseByIoc(caseRecord, normalizedValue) {
  const sourceAlert = caseRecord?.alert || null;
  const linkedAlerts = Array.isArray(caseRecord?.linkedAlerts)
    ? caseRecord.linkedAlerts
    : (Array.isArray(caseRecord?.linked_alerts) ? caseRecord.linked_alerts : []);
  return [sourceAlert, ...linkedAlerts]
    .filter(Boolean)
    .some(alert => buildIocEntriesForAlert(alert).some(entry => entry.normalizedValue === normalizedValue));
}

export function buildLocalIocPivotPayload({
  iocType,
  value,
  alerts = [],
  cases = [],
  activityEntries = [],
  watchlist = []
}) {
  const normalizedType = normalizeIocType(iocType);
  const rawValue = safeString(value);
  const normalizedValue = normalizeIocValue(normalizedType, rawValue);

  const relatedAlerts = (Array.isArray(alerts) ? alerts : []).filter(alert =>
    buildIocEntriesForAlert(alert).some(entry =>
      entry.type === normalizedType && entry.normalizedValue === normalizedValue
    )
  );

  const relatedCases = (Array.isArray(cases) ? cases : [])
    .filter(caseRecord => matchesCaseByIoc(caseRecord, normalizedValue))
    .filter((caseRecord, index, collection) =>
      collection.findIndex(candidate => String(candidate?.id || "") === String(caseRecord?.id || "")) === index
    );

  const recentActivity = (Array.isArray(activityEntries) ? activityEntries : [])
    .filter(entry => buildActivityHaystack(entry).includes(normalizedValue))
    .sort((left, right) => Number(right?.timestamp || 0) - Number(left?.timestamp || 0));

  const watchlistEntry = (Array.isArray(watchlist) ? watchlist : []).find(entry =>
    normalizeIocType(entry?.type) === normalizedType
      && normalizeIocValue(normalizedType, entry?.value) === normalizedValue
  ) || null;

  return {
    ioc: {
      type: normalizedType,
      value: rawValue,
      normalized_value: normalizedValue
    },
    summary: {
      related_alerts_count: relatedAlerts.length,
      related_cases_count: relatedCases.length,
      activity_count: recentActivity.length,
      recurrence_count: relatedAlerts.length,
      watchlist_hit: Boolean(watchlistEntry)
    },
    watchlist_entry: watchlistEntry,
    related_alerts: relatedAlerts.slice(0, 50).map(alert => ({
      id: alert.id,
      attack_type: alert.attackType || alert.attack_type || alert.rule || "alert",
      severity: alert.severity || "medium",
      timestamp: alert.timestamp || alert.createdAt || alert.created_at || null,
      status: alert.status || alert.lifecycle || "new",
      case_id: alert.mergedIntoCaseId || alert.caseId || alert.case_id || null,
      case_name: relatedCases.find(caseRecord =>
        String(caseRecord?.id || "") === String(alert.mergedIntoCaseId || alert.caseId || alert.case_id || "")
      )?.title || null
    })),
    related_cases: relatedCases.slice(0, 25).map(caseRecord => ({
      id: caseRecord.id,
      case_id: caseRecord.id,
      case_name: caseRecord.title || caseRecord.case_name || caseRecord.id,
      priority: caseRecord.priority || "medium",
      assignee: caseRecord.assignee || null,
      status: caseRecord.status || "open",
      updated_at: caseRecord.updated_at || caseRecord.updatedAt || caseRecord.created_at || null
    })),
    recent_activity: recentActivity.slice(0, 50).map(entry => ({
      timestamp: entry.timestamp || null,
      action: entry.actionType || entry.action || "activity",
      actor: entry.actor || entry.user || "Unknown",
      object_type: entry.targetType || entry.target_type || "",
      object_id: entry.targetId || entry.target_id || "",
      message: entry.message || ""
    }))
  };
}
