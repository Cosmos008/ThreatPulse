const FIELD_KEYS = {
  ip: ["sourceIp", "source_ip", "ip"],
  user: ["userId", "user_id", "username"],
  attack: ["attackType", "attack_type", "rule"],
  country: ["country"],
  severity: ["severity"],
  status: ["status", "lifecycle"]
};

const TIME_RANGE_SECONDS = {
  "5m": 5 * 60,
  "1h": 60 * 60,
  "24h": 24 * 60 * 60
};

function safeString(value) {
  return String(value || "").trim();
}

export function parseHuntQuery(query, explicitTimeRange = "") {
  let workingQuery = safeString(query);
  let resolvedTimeRange = safeString(explicitTimeRange).toLowerCase();
  const match = workingQuery.match(/\blast\s+(5\s*(?:m|min|mins|minute|minutes)|1\s*(?:h|hr|hour|hours)|24\s*(?:h|hr|hour|hours))\b/i);
  if (match && !resolvedTimeRange) {
    const compact = match[1].replace(/\s+/g, "").toLowerCase();
    resolvedTimeRange = compact.startsWith("5") ? "5m" : (compact.startsWith("1") ? "1h" : "24h");
    workingQuery = `${workingQuery.slice(0, match.index)} ${workingQuery.slice((match.index || 0) + match[0].length)}`.trim();
  }
  if (!TIME_RANGE_SECONDS[resolvedTimeRange]) {
    resolvedTimeRange = "24h";
  }
  const groups = workingQuery
    ? workingQuery.split(/\s+OR\s+/i).map(segment => segment.trim()).filter(Boolean).map(segment =>
      segment.split(/\s+AND\s+/i).map(term => term.trim()).filter(Boolean).map(term => {
        const separator = term.indexOf(":");
        if (separator > 0) {
          const field = safeString(term.slice(0, separator)).toLowerCase();
          const value = safeString(term.slice(separator + 1));
          if (FIELD_KEYS[field] && value) {
            return { field, value };
          }
        }
        return { field: "text", value: term };
      })
    )
    : [];
  return {
    query: workingQuery,
    groups,
    timeRange: resolvedTimeRange
  };
}

function getFieldValues(alert, field) {
  const keys = FIELD_KEYS[field] || [];
  const values = keys.map(key => safeString(alert?.[key] ?? alert?.details?.[key] ?? alert?.raw?.[key] ?? alert?.raw?.details?.[key])).filter(Boolean);
  if (field === "text") {
    return [
      safeString(alert?.sourceIp || alert?.source_ip || alert?.ip),
      safeString(alert?.userId || alert?.user_id || alert?.details?.user_id),
      safeString(alert?.attackType || alert?.attack_type || alert?.rule),
      safeString(alert?.country),
      safeString(alert?.severity),
      safeString(alert?.status),
      safeString(alert?.details),
    ].filter(Boolean);
  }
  return values;
}

function normalizeTimestamp(value) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value > 9999999999 ? value : value;
  }
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? Date.now() : parsed;
}

function matchesTerm(alert, term) {
  const expected = safeString(term?.value).toLowerCase();
  if (!expected) {
    return true;
  }
  return getFieldValues(alert, term?.field).some(value => safeString(value).toLowerCase().includes(expected));
}

export function filterAlertsByHuntQuery(alerts, query, explicitTimeRange = "") {
  const parsed = parseHuntQuery(query, explicitTimeRange);
  const cutoff = Date.now() - (TIME_RANGE_SECONDS[parsed.timeRange] || TIME_RANGE_SECONDS["24h"]) * 1000;
  const matchesQuery = alert => {
    if (!parsed.groups.length) {
      return true;
    }
    return parsed.groups.some(group => group.every(term => matchesTerm(alert, term)));
  };
  return (Array.isArray(alerts) ? alerts : []).filter(alert => normalizeTimestamp(alert?.timestamp || alert?.createdAt || alert?.created_at) >= cutoff && matchesQuery(alert));
}

export function buildPivotHuntQuery(field, value, timeRange = "") {
  const normalizedField = safeString(field).toLowerCase();
  const normalizedValue = safeString(value);
  if (!normalizedField || !normalizedValue) {
    return "";
  }
  const query = `${normalizedField}:${normalizedValue}`;
  return timeRange ? `${query} last ${timeRange}` : query;
}
