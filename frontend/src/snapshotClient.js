function normalizeBaseUrl(value, fallback) {
  return (value || fallback).replace(/\/+$/, "");
}

function buildGeolocationBaseUrl(apiBaseUrl) {
  const url = new URL(normalizeBaseUrl(apiBaseUrl, ""));
  url.port = "8002";
  url.pathname = "";
  url.search = "";
  url.hash = "";
  return url.toString().replace(/\/+$/, "");
}

function readNumber(...values) {
  for (const value of values) {
    const numeric = Number(value);
    if (Number.isFinite(numeric)) {
      return numeric;
    }
  }
  return null;
}

function normalizeTimestamp(value) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value > 9999999999 ? value : value * 1000;
  }

  if (typeof value === "string") {
    const numeric = Number(value);
    if (!Number.isNaN(numeric)) {
      return numeric > 9999999999 ? numeric : numeric * 1000;
    }

    const parsed = Date.parse(value);
    if (!Number.isNaN(parsed)) {
      return parsed;
    }
  }

  return Date.now();
}

function normalizeSeverity(value) {
  const severity = String(value || "medium").toLowerCase();
  if (severity === "critical" || severity === "high" || severity === "medium" || severity === "low") {
    return severity;
  }
  return "medium";
}

function buildHeaders(apiKey, username) {
  const headers = {
    "X-API-Key": apiKey,
  };
  if (username) {
    headers["X-User"] = username;
  }
  return headers;
}

function normalizeEvent(payload) {
  const details = payload.details || {};
  const sequence = payload.sequence || details.sequence || null;
  const explanation = Array.isArray(payload.explanation)
    ? payload.explanation
    : (Array.isArray(details.explanation) ? details.explanation : []);
  const riskHistory = Array.isArray(payload.risk_history)
    ? payload.risk_history
    : (Array.isArray(details.risk_history) ? details.risk_history : []);
  const mitre = payload.mitre || details.mitre || null;
  const threatLevel = payload.threat_level || details.threat_level || null;
  const status = payload.status || details.status || "open";
  const falsePositive = Boolean(payload.false_positive || details.false_positive);
  const analyst = payload.analyst || details.analyst || null;
  const notes = Array.isArray(payload.notes)
    ? payload.notes
    : (Array.isArray(details.notes) ? details.notes : []);
  const lockedBy = payload.locked_by || details.locked_by || null;
  const createdAt = normalizeTimestamp(payload.created_at || details.created_at || payload.timestamp || details.timestamp);
  const attackType = payload.attack_type || payload.rule || details.attack_type || details.rule || "alert";
  let severity = normalizeSeverity(payload.severity || details.severity);
  const riskScore = Number(payload.risk_score ?? details.risk_score ?? details.reputation_score ?? 0) || 0;
  const deviceId = details.device_hash || details.device_id || payload.device_hash || payload.device_id || "Unknown";
  const userId = details.user_id || payload.user_id || "Unknown";
  const country = payload.country || details.country_code || details.country || "Unknown";
  const sourceIp = payload.source_ip || payload.ip || details.source_ip || details.ip || "unknown";
  const timestamp = normalizeTimestamp(payload.timestamp || details.timestamp);
  const entityContext = payload.entity_context || details.entity_context || {};
  const isHoneypot = attackType === "honeypot_access" || Boolean(payload.is_honeypot || details.is_honeypot);
  const isTor = attackType === "tor_exit_node" || Boolean(details.is_tor || payload.is_tor);
  const isProxy = attackType === "proxy_usage" || Boolean(details.is_proxy || payload.is_proxy);
  const isHighRisk = attackType === "high_risk_actor" || riskScore >= 120;
  const confidenceLabel = payload.confidence_label || details.confidence_label || (isHoneypot ? "High confidence threat" : null);
  const indicators = [
    isHoneypot ? "Honeypot" : null,
    confidenceLabel,
    isTor ? "TOR node" : null,
    isProxy ? "Proxy" : null,
    isHighRisk ? "High risk" : null
  ].filter(Boolean);

  if (isHoneypot) {
    severity = "critical";
  }

  return {
    id: payload.id || `${sourceIp}-${attackType}-${timestamp}`,
    sourceIp,
    sourceLat: readNumber(payload.source_lat, payload.lat, payload.latitude, details.source_lat, details.lat),
    sourceLon: readNumber(payload.source_lon, payload.lon, payload.longitude, details.source_lon, details.lon),
    targetLat: readNumber(payload.target_lat, payload.target_latitude, details.target_lat, 51.5072),
    targetLon: readNumber(payload.target_lon, payload.target_longitude, details.target_lon, -0.1276),
    country,
    attackType,
    timestamp,
    severity,
    riskScore,
    userId,
    deviceId,
    indicators,
    isHoneypot,
    isTor,
    isProxy,
    isHighRisk,
    confidenceLabel,
    explanation,
    riskHistory,
    mitre,
    threatLevel,
    status,
    falsePositive,
    analyst,
    notes,
    lockedBy,
    createdAt,
    sequence,
    entityContext,
    details,
    raw: payload
  };
}

async function lookupCountries(apiBaseUrl, apiKey, sourceIps, username) {
  if (!sourceIps.length) {
    return new Map();
  }

  const response = await fetch(`${buildGeolocationBaseUrl(apiBaseUrl)}/lookup`, {
    method: "POST",
    headers: {
      ...buildHeaders(apiKey, username),
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ ips: sourceIps })
  });

  if (!response.ok) {
    return new Map();
  }

  const payload = await response.json();
  const results = Array.isArray(payload?.results) ? payload.results : [];
  return new Map(
    results
      .filter(result => result?.ip)
      .map(result => [result.ip, result.country_code || result.country || "Unknown"])
  );
}

async function fetchJson(url, apiKey, username) {
  const response = await fetch(url, {
    headers: buildHeaders(apiKey, username)
  });

  if (!response.ok) {
    let detail = "";
    try {
      const payload = await response.json();
      detail = payload?.detail || payload?.message || "";
    } catch {
      detail = "";
    }

    if (response.status === 401) {
      throw new Error(detail || "Authentication failed. Check the API key.");
    }

    if (response.status === 429) {
      throw new Error(detail || "Rate limit exceeded. Try again shortly.");
    }

    throw new Error(detail || `Request failed with status ${response.status}`);
  }

  return response.json();
}

export async function fetchAlertSnapshot(apiBaseUrl, apiKey, username) {
  const payload = await fetchJson(`${normalizeBaseUrl(apiBaseUrl, "")}/alerts`, apiKey, username);
  const alerts = Array.isArray(payload?.alerts) ? payload.alerts : [];
  const normalizedAlerts = alerts.map(normalizeEvent);
  const unresolvedIps = [...new Set(
    normalizedAlerts
      .filter(alert => alert.country === "Unknown" && alert.sourceIp && alert.sourceIp !== "unknown")
      .map(alert => alert.sourceIp)
  )];
  const countriesByIp = await lookupCountries(apiBaseUrl, apiKey, unresolvedIps, username);

  return normalizedAlerts.map(alert => ({
    ...alert,
    country: countriesByIp.get(alert.sourceIp) || alert.country
  }));
}

export async function fetchStreamToken(apiBaseUrl, apiKey, username) {
  const response = await fetch(`${normalizeBaseUrl(apiBaseUrl, "")}/auth/token`, {
    method: "POST",
    headers: buildHeaders(apiKey, username)
  });

  if (!response.ok) {
    let detail = "";
    try {
      const payload = await response.json();
      detail = payload?.detail || payload?.message || "";
    } catch {
      detail = "";
    }
    throw new Error(detail || `Token request failed with status ${response.status}`);
  }

  const payload = await response.json();
  if (!payload?.token) {
    throw new Error("Token response did not include a websocket token.");
  }

  return payload.token;
}

export function normalizeAlertEvent(payload) {
  return normalizeEvent(payload);
}
