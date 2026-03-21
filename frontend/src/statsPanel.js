import { workbenchState, setSelectedAlertId, setSelectedEntityKey } from "./core/workbenchState.js";
import { buildIocChipGroups, highlightIocsInText, normalizeAlertEnrichment } from "./core/alertEnrichment.js";
import { buildEntityContextForAlert } from "./core/entityProfiles.js";
import { buildIocPivotTriggerMarkup } from "./core/iocPivot.js";
import {
  getAlertLifecycleLabel,
  isAlertEligibleForTriage,
  normalizeAlertLifecycle
} from "./core/alertLifecycle.js";
import { correlateRelatedAlerts } from "./core/correlation.js";
import { getIpReputation } from "./core/reputationService.js";
import { buildAlertDetailMarkup } from "./views/alertDetailView.js";

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function normalizeTimestamp(timestamp) {
  if (typeof timestamp === "number") {
    return timestamp > 9999999999 ? timestamp : timestamp * 1000;
  }

  const parsed = Date.parse(timestamp);
  if (!Number.isNaN(parsed)) {
    return parsed;
  }

  return Date.now();
}

function formatTimestamp(timestamp) {
  return new Date(normalizeTimestamp(timestamp)).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

function formatDateTime(timestamp) {
  return new Date(normalizeTimestamp(timestamp)).toLocaleString([], {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

function formatDuration(seconds) {
  const numeric = Number(seconds);
  if (!Number.isFinite(numeric) || numeric < 0) {
    return "Pending";
  }
  const totalSeconds = Math.floor(numeric);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const remainingSeconds = totalSeconds % 60;
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${remainingSeconds}s`;
  }
  return `${remainingSeconds}s`;
}

function getActiveDurationSeconds(startTimestamp, now = Date.now()) {
  const normalizedStart = normalizeTimestamp(startTimestamp);
  return Math.max(0, Math.floor((now - normalizedStart) / 1000));
}

function buildTimelineBuckets(now = Date.now()) {
  const bucketSizeMs = 5000;
  const bucketCount = 12;
  const alignedNow = Math.floor(now / bucketSizeMs) * bucketSizeMs;

  return Array.from({ length: bucketCount }, (_, index) => {
    const bucketStart = alignedNow - ((bucketCount - 1 - index) * bucketSizeMs);
    return {
      start: bucketStart,
      end: bucketStart + bucketSizeMs,
      label: formatTimestamp(bucketStart),
      count: 0
    };
  });
}

function buildHeatmapBuckets(alerts, now = Date.now()) {
  const buckets = Array(12).fill(0);

  alerts.forEach(alert => {
    const diff = now - normalizeTimestamp(alert.timestamp);
    const index = Math.floor(diff / 5000);

    if (index >= 0 && index < 12) {
      buckets[11 - index] += 1;
    }
  });

  return buckets;
}

function getBarColor(value) {
  if (value >= 6) {
    return "high";
  }
  if (value >= 3) {
    return "medium";
  }
  return "low";
}

function getThemeValue(name, fallback) {
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value || fallback;
}

function hexToRgba(hex, alpha) {
  const normalized = hex.replace("#", "");
  if (normalized.length !== 6) {
    return `rgba(15, 98, 254, ${alpha})`;
  }

  const red = Number.parseInt(normalized.slice(0, 2), 16);
  const green = Number.parseInt(normalized.slice(2, 4), 16);
  const blue = Number.parseInt(normalized.slice(4, 6), 16);
  return `rgba(${red}, ${green}, ${blue}, ${alpha})`;
}

function buildBarGradient(context, chartArea, intensity) {
  const palette = {
    low: getThemeValue("--chart-low", "#0f62fe"),
    medium: getThemeValue("--chart-medium", "#f59e0b"),
    high: getThemeValue("--chart-high", "#dc3545")
  };
  const base = palette[intensity] || palette.low;
  const gradient = context.createLinearGradient(0, chartArea.bottom, 0, chartArea.top);

  gradient.addColorStop(0, hexToRgba(base, 0.28));
  gradient.addColorStop(0.55, hexToRgba(base, 0.72));
  gradient.addColorStop(1, hexToRgba(base, 0.98));
  return gradient;
}

function getSeverityWeight(severity) {
  const mapping = {
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
  };
  return mapping[severity] || 2;
}

function getSlaThresholds(severity) {
  const mapping = {
    critical: { ack: 5 * 60, close: 30 * 60 },
    high: { ack: 15 * 60, close: 2 * 60 * 60 },
    medium: { ack: 60 * 60, close: 8 * 60 * 60 },
    low: { ack: 60 * 60, close: 8 * 60 * 60 }
  };
  return mapping[String(severity || "medium").toLowerCase()] || mapping.medium;
}

function getLiveSlaState(alert, now = Date.now()) {
  const createdAt = normalizeTimestamp(alert?.createdAt || alert?.created_at || alert?.timestamp || now);
  const acknowledgedAt = alert?.acknowledgedAt != null ? normalizeTimestamp(alert.acknowledgedAt) : null;
  const closedAt = alert?.closedAt != null ? normalizeTimestamp(alert.closedAt) : null;
  const thresholds = alert?.slaThresholds || getSlaThresholds(alert?.severity);
  const timeToAck = acknowledgedAt != null
    ? Math.max(0, Math.floor((acknowledgedAt - createdAt) / 1000))
    : null;
  const timeToClose = closedAt != null
    ? Math.max(0, Math.floor((closedAt - createdAt) / 1000))
    : null;
  const ackElapsed = Math.max(0, Math.floor((now - createdAt) / 1000));
  const closeElapsed = closedAt != null ? timeToClose : ackElapsed;
  const ackOverdue = (acknowledgedAt != null
    ? Math.floor((acknowledgedAt - createdAt) / 1000) > thresholds.ack
    : ackElapsed > thresholds.ack);
  const closeOverdue = (closedAt != null
    ? Math.floor((closedAt - createdAt) / 1000) > thresholds.close
    : closeElapsed > thresholds.close);
  const overdue = ackOverdue || closeOverdue || Boolean(alert?.overdue);
  const riskScore = Number(alert?.riskScore || 0);
  const urgencyScore = Math.round((
    (getSeverityWeight(alert?.severity) * 12)
    + Math.min(40, riskScore / 3)
    + Math.min(40, ackElapsed / 300)
    + (overdue ? 20 : 0)
  ) * 100) / 100;
  return {
    thresholds,
    timeToAck,
    timeToClose,
    ackElapsed,
    closeElapsed,
    ackOverdue,
    closeOverdue,
    overdue,
    urgencyScore
  };
}

function getAlertPriorityRisk(alert) {
  return Number(alert?.riskScore) || getSeverityWeight(alert?.severity) || 0;
}

function sortAlertsByPriority(left, right) {
  const riskDiff = getAlertPriorityRisk(right) - getAlertPriorityRisk(left);
  if (riskDiff !== 0) {
    return riskDiff;
  }
  return normalizeTimestamp(right.timestamp) - normalizeTimestamp(left.timestamp);
}

function getSeverityLabel(severity) {
  return String(severity || "medium").toUpperCase();
}

function normalizeSeverity(severity) {
  const value = String(severity || "medium").toLowerCase();
  if (value === "critical" || value === "high" || value === "medium" || value === "low") {
    return value;
  }
  return "medium";
}

function getSeverityClass(severity) {
  switch (String(severity || "").toLowerCase()) {
    case "critical":
      return "sev-critical";
    case "high":
      return "sev-high";
    case "medium":
      return "sev-medium";
    case "low":
      return "sev-low";
    default:
      return "sev-unknown";
  }
}

const mitreMap = {
  credential_stuffing: { technique: "T1110", id: "T1110", name: "Brute Force", tactic: "Credential Access" },
  honeypot_access: { technique: "T1190", id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  rate_limit_abuse: { technique: "T1499", id: "T1499", name: "Endpoint Denial of Service", tactic: "Impact" }
};

function buildAlertId(alert, timestamp) {
  return alert.id || `${alert.sourceIp || "unknown"}-${alert.attackType || "alert"}-${timestamp}`;
}

function getUiState() {
  return window.__dashboardUiState || {
    isUserInteracting: false,
    selectedAnalystByAlert: {}
  };
}

function isAdminUser() {
  return Boolean(window.__dashboardIsAdmin?.());
}

function getCurrentDashboardUser() {
  return window.__dashboardGetCurrentUser?.() || null;
}

function normalizeStoredAlert(alert) {
  const timestamp = normalizeTimestamp(alert.timestamp);
  const isHoneypot = Boolean(alert.isHoneypot || alert.is_honeypot || alert.attackType === "honeypot_access" || alert.attack_type === "honeypot_access");
  const coordinatedAttack = Boolean(
    alert.coordinatedAttack ||
    alert.coordinated_attack ||
    alert.attackType === "coordinated_attack" ||
    alert.attack_type === "coordinated_attack" ||
    alert.details?.coordinated_attack
  );
  const severity = isHoneypot ? "critical" : normalizeSeverity(alert.severity);
  const sourceIp = alert.sourceIp || alert.source_ip || "unknown";
  const attackType = alert.attackType || alert.attack_type || "alert";
  const confidenceLabel = alert.confidenceLabel || alert.confidence_label || (isHoneypot ? "High confidence threat" : null);
  const sequence = alert.sequence || alert.details?.sequence || null;
  const explanation = Array.isArray(alert.explanation)
    ? alert.explanation
    : (Array.isArray(alert.details?.explanation) ? alert.details.explanation : []);
  const riskHistory = Array.isArray(alert.riskHistory)
    ? alert.riskHistory
    : (Array.isArray(alert.risk_history) ? alert.risk_history : []);
  const mitre = alert.mitre || alert.details?.mitre || null;
  const threatLevel = alert.threatLevel || alert.threat_level || alert.details?.threat_level || null;
  const isBlocked = Boolean(alert.isBlocked || alert.is_blocked || alert.details?.is_blocked);
  const status = normalizeAlertLifecycle({
    ...alert,
    status: String(alert.status || alert.details?.status || "new").toLowerCase()
  });
  const falsePositive = Boolean(alert.falsePositive || alert.false_positive || alert.details?.false_positive);
  const analyst = getUiState().selectedAnalystByAlert[buildAlertId(alert, timestamp)] || alert.assigned_to || alert.analyst || alert.details?.assigned_to || alert.details?.analyst || null;
  const notes = Array.isArray(alert.notes)
    ? alert.notes
    : (Array.isArray(alert.details?.notes) ? alert.details.notes : []);
  const lockedBy = alert.lockedBy || alert.locked_by || alert.details?.locked_by || null;
  const createdAt = normalizeTimestamp(alert.createdAt || alert.created_at || alert.details?.created_at || timestamp);
  const updatedAt = normalizeTimestamp(alert.updatedAt || alert.updated_at || alert.details?.updated_at || createdAt);
  const acknowledgedAt = alert.acknowledgedAt || alert.acknowledged_at || alert.details?.acknowledged_at || null;
  const closedAt = alert.closedAt || alert.closed_at || alert.details?.closed_at || null;
  const indicators = [...new Set([
    ...(Array.isArray(alert.indicators) ? alert.indicators.filter(Boolean) : []),
    isHoneypot ? "Honeypot" : null,
    coordinatedAttack ? "Multi-stage attack detected" : null,
    isBlocked ? "Blocked" : null,
    falsePositive ? "False Positive" : null,
    confidenceLabel
  ].filter(Boolean))];

  return {
    ...alert,
    id: buildAlertId(alert, timestamp),
    timestamp,
    severity,
    sourceIp,
    attackType,
    country: alert.country || "Unknown",
    userId: alert.userId || alert.user_id || "Unknown",
    deviceId: alert.deviceId || alert.device_id || "Unknown",
    riskScore: Number(alert.riskScore ?? alert.risk_score ?? 0) || 0,
    indicators,
    isHoneypot,
    coordinatedAttack,
    isTor: Boolean(alert.isTor),
    isProxy: Boolean(alert.isProxy),
    isHighRisk: Boolean(alert.isHighRisk),
    confidenceLabel,
    sequence,
    explanation,
    riskHistory,
    mitre,
    threatLevel,
    isBlocked,
    status,
    lifecycle: status,
    falsePositive,
    analyst,
    assignedTo: analyst,
    notes,
    lockedBy,
    createdAt,
    updatedAt,
    acknowledgedAt,
    closedAt,
    timeToAck: Number(alert.timeToAck ?? alert.time_to_ack ?? alert.details?.time_to_ack ?? 0) || null,
    timeToClose: Number(alert.timeToClose ?? alert.time_to_close ?? alert.details?.time_to_close ?? 0) || null,
    overdue: Boolean(alert.overdue ?? alert.details?.overdue),
    urgencyScore: Number(alert.urgencyScore ?? alert.urgency_score ?? alert.details?.urgency_score ?? 0) || 0,
    watchlistHit: Boolean(alert.watchlistHit ?? alert.watchlist_hit ?? alert.details?.watchlist_hit),
    watchlistHitsCount: Number(alert.watchlistHitsCount ?? alert.watchlist_hits_count ?? alert.details?.watchlist_hits_count ?? 0) || 0,
    watchlistMatches: Array.isArray(alert.watchlistMatches || alert.watchlist_matches || alert.details?.watchlist_matches)
      ? (alert.watchlistMatches || alert.watchlist_matches || alert.details?.watchlist_matches)
      : [],
    slaThresholds: alert.slaThresholds || alert.sla_thresholds || alert.details?.sla_thresholds || getSlaThresholds(severity),
    slaBreaches: alert.slaBreaches || alert.sla_breaches || alert.details?.sla_breaches || null,
    mergedIntoCaseId: alert.mergedIntoCaseId || alert.merged_into_case_id || alert.caseId || alert.case_id || "",
    recommendation: getAlertRecommendation({ ...alert, attackType }),
    raw: alert.raw || alert
  };
}

function renderEnrichmentGroup(title, fields) {
  const rows = fields.filter(field => field.value).map(field => `
    <span><strong>${escapeHtml(field.label)}:</strong> ${field.iocType ? buildIocPivotTriggerMarkup(field.iocType, field.value) : escapeHtml(field.value)}</span>
  `).join("");
  if (!rows) {
    return "";
  }
  return `
    <div class="detail-section enrichment-section">
      <strong>${escapeHtml(title)}</strong>
      <div class="detail-grid">${rows}</div>
    </div>
  `;
}

function renderIocSection(alert) {
  const groups = buildIocChipGroups(alert);
  if (!groups.length) {
    return "";
  }
  return `
    <div class="detail-section enrichment-section">
      <strong>Indicators of Compromise</strong>
      <div class="ioc-groups">
        ${groups.map(group => `
          <div class="ioc-group">
            <span class="ioc-group-label">${escapeHtml(group.label)}</span>
            <div class="ioc-chip-list">
              ${group.values.map(value => buildIocPivotTriggerMarkup(group.key, value, { className: "ioc-chip" })).join("")}
            </div>
          </div>
        `).join("")}
      </div>
    </div>
  `;
}


function getRiskLevel(score) {
  if (score >= 100) {
    return "high";
  }
  if (score >= 50) {
    return "medium";
  }
  return "low";
}

function renderRiskScore(score) {
  const level = getRiskLevel(score);
  return `<span class="risk-score risk-score-${level}">${escapeHtml(String(score))}</span>`;
}

function renderRiskEvolution(history = []) {
  if (!history.length) {
    return "";
  }

  return `
    <div class="risk-evolution">
      <h4>Risk Score Evolution</h4>
      <div class="risk-values">
        ${history.map(entry => `<span>${escapeHtml(String(entry.score ?? 0))}</span>`).join(" -> ")}
      </div>
    </div>
  `;
}

function renderThreatLevel(threatLevel) {
  if (!threatLevel) {
    return "";
  }

  const tone = String(threatLevel).toLowerCase();
  return `<span class="threat-level ${escapeHtml(tone)}">${escapeHtml(threatLevel)}</span>`;
}

function renderHuntPivot(field, value, label = value) {
  if (!value) {
    return "";
  }
  return `<button type="button" class="hunt-inline-pivot" data-hunt-query-field="${escapeHtml(field)}" data-hunt-query-value="${escapeHtml(String(value))}">${escapeHtml(String(label))}</button>`;
}

function formatEntityType(entityType) {
  const labels = {
    ip: "IP",
    user: "User",
    host: "Host"
  };
  return labels[String(entityType || "").toLowerCase()] || "Entity";
}

function formatRelativeOrAbsoluteTime(timestamp) {
  if (!timestamp) {
    return "Unknown";
  }
  return formatDateTime(timestamp);
}

function renderEntityContextPanels(entityContext = {}) {
  const profiles = ["ip", "user", "host"]
    .map(type => entityContext?.[type])
    .filter(Boolean);
  if (!profiles.length) {
    return '<div class="detail-empty-inline">No entity context available for this alert.</div>';
  }

  return `<div class="entity-context-grid">
    ${profiles.map(profile => `
      <button type="button" class="entity-context-card" data-entity-type="${escapeHtml(profile.entity_type)}" data-entity-key="${escapeHtml(profile.entity_key)}">
        <div class="entity-context-top">
          <span class="entity-context-kind">${escapeHtml(formatEntityType(profile.entity_type))}</span>
          <span class="entity-criticality entity-criticality-${escapeHtml(String(profile.asset_criticality || "medium").toLowerCase())}">${escapeHtml(String(profile.asset_criticality || "medium").toUpperCase())}</span>
        </div>
        <strong>${escapeHtml(profile.display_name || profile.entity_key)}</strong>
        <div class="entity-context-metrics">
          <span>Risk ${renderRiskScore(Number(profile.risk_score || 0))}</span>
          <span>${escapeHtml(String(profile.alert_count || 0))} alerts</span>
          <span>${escapeHtml(String(profile.case_count || 0))} cases</span>
        </div>
        <div class="entity-context-meta">
          <span>First seen ${escapeHtml(formatRelativeOrAbsoluteTime(profile.first_seen))}</span>
          <span>Last seen ${escapeHtml(formatRelativeOrAbsoluteTime(profile.last_seen))}</span>
        </div>
        <div class="attack-type-list">
          ${(Array.isArray(profile.related_attack_types) ? profile.related_attack_types : []).slice(0, 4).map(type => `<span class="attack-type-chip">${escapeHtml(type)}</span>`).join("")}
        </div>
      </button>
    `).join("")}
  </div>`;
}

function renderMitre(mitre, attackType) {
  const resolvedMitre = mitre || mitreMap[attackType] || null;
  if (!resolvedMitre) {
    return "";
  }

  return `
    <div class="mitre-block mitre-box">
      <h4>MITRE ATT&CK Mapping</h4>
      <div class="mitre-item">
        <strong>${escapeHtml(resolvedMitre.technique || resolvedMitre.id || "Unknown")}</strong> - ${escapeHtml(resolvedMitre.name || "Unknown")}
      </div>
      <div class="mitre-tactic">${escapeHtml(resolvedMitre.tactic || "Unknown")}</div>
    </div>
  `;
}

function getAlertRecommendation(alert) {
  const mapping = {
    credential_stuffing: "Apply rate limiting and review failed-login thresholds.",
    honeypot_access: "Block the source immediately and isolate related accounts or devices.",
    anomaly_spike: "Investigate the user and IP for unusual behavior and linked alerts.",
  };

  return alert.recommendation || mapping[alert.attackType] || "Review the full event context and monitor for follow-up activity.";
}

function getSequenceLabel(sequenceType) {
  const mapping = {
    suspicious: "Suspicious sequence",
    coordinated: "Coordinated attack",
    critical: "Critical multi-stage attack"
  };
  return mapping[sequenceType] || "Suspicious sequence";
}

function renderSequenceTypeBadge(sequenceType) {
  if (!sequenceType || sequenceType === "single") {
    return "";
  }

  const tone = sequenceType === "critical" ? "critical" : "coordinated";
  return `<span class="sequence-type-badge sequence-type-${tone}">${escapeHtml(getSequenceLabel(sequenceType))}</span>`;
}

function renderSeverityBadge(severity) {
  return `<span class="severity-badge ${getSeverityClass(severity)}">${escapeHtml(String(severity || "unknown").toUpperCase())}</span>`;
}

function renderBlockedBadge(isBlocked) {
  if (!isBlocked) {
    return "";
  }
  return '<span class="blocked-badge">Blocked</span>';
}

function renderAlertStatus(status) {
  const lifecycle = normalizeAlertLifecycle({ status });
  return `<span class="alert-status ${escapeHtml(lifecycle)}">${escapeHtml(getAlertLifecycleLabel(lifecycle).toUpperCase())}</span>`;
}

function renderOverdueBadge(alert, now = Date.now()) {
  const liveSla = getLiveSlaState(alert, now);
  const overdue = Boolean(liveSla.overdue);
  if (!overdue) {
    return "";
  }
  const title = liveSla.ackOverdue && liveSla.closeOverdue
    ? "Acknowledge and close SLA breached"
    : (liveSla.ackOverdue ? "Acknowledge SLA breached" : "Close SLA breached");
  return `<span class="overdue-badge" title="${escapeHtml(title)}">Overdue</span>`;
}

function renderWatchlistBadge(alert) {
  if (!alert?.watchlistHit) {
    return "";
  }
  const count = Number(alert.watchlistHitsCount || 0);
  const label = count > 0 ? `Watchlist · ${count}` : "Watchlist";
  return `<span class="watchlist-badge">${escapeHtml(label)}</span>`;
}

function renderSlaSummary(alert, now = Date.now()) {
  const liveSla = getLiveSlaState(alert, now);
  const ackValue = liveSla.timeToAck != null ? formatDuration(liveSla.timeToAck) : formatDuration(liveSla.ackElapsed);
  const closeValue = liveSla.timeToClose != null ? formatDuration(liveSla.timeToClose) : formatDuration(liveSla.closeElapsed);
  return `
    <span><strong>Time to acknowledge:</strong> ${escapeHtml(ackValue)}</span>
    <span><strong>Time to close:</strong> ${escapeHtml(closeValue)}</span>
  `;
}

function renderFalsePositiveBadge(falsePositive) {
  if (!falsePositive) {
    return "";
  }
  return '<span class="false-positive-badge">False Positive</span>';
}

function renderAnalyst(analyst) {
  if (!analyst) {
    return "";
  }
  return `<span class="assigned-analyst">Assigned to: ${escapeHtml(analyst)}</span>`;
}

function getSlaState(createdAt) {
  const ageMs = Date.now() - normalizeTimestamp(createdAt);
  if (ageMs > 60_000) {
    return "breach";
  }
  if (ageMs > 30_000) {
    return "warning";
  }
  return "ok";
}

function renderLockBadge(lockedBy) {
  if (!lockedBy) {
    return "";
  }
  return `<span class="lock-badge">Lock: ${escapeHtml(lockedBy)}</span>`;
}

function renderSlaBadge(createdAt) {
  const state = getSlaState(createdAt);
  const label = {
    ok: "SLA OK",
    warning: "SLA Warning",
    breach: "SLA Breach"
  }[state];
  return `<span class="sla-badge sla-${state}">${escapeHtml(label)}</span>`;
}

function renderOwnerBadge(analyst) {
  if (analyst) {
    return `<span class="owner-badge">${escapeHtml(analyst)}</span>`;
  }
  return '<span class="unassigned">Unassigned</span>';
}

function cleanTarget(target) {
  if (!target) {
    return "";
  }

  const value = String(target);
  if (value.includes(":")) {
    return value.split(":").slice(1).join(":") || value;
  }
  return value.split("-")[0];
}

function formatAction(historyItem) {
  const user = historyItem.user || "Unknown";
  const cleaned = cleanTarget(historyItem.target);

  switch (historyItem.action) {
    case "assign_alert":
      return `Assigned by ${user} to ${cleaned || "alert"}`;
    case "set_status":
      return `${user} set status to ${cleaned || "updated"}`;
    case "block_ip":
      return `${user} blocked IP ${cleaned || "unknown"}`;
    case "add_note":
      return `${user} added a note`;
    case "false_positive":
      return `${user} marked this as false positive`;
    default:
      return `${user} -> ${historyItem.action || "action"}`;
  }
}

function timeAgo(timestamp) {
  const normalized = normalizeTimestamp(timestamp);
  const diffSeconds = Math.max(0, Math.floor((Date.now() - normalized) / 1000));

  if (diffSeconds < 60) {
    return `${diffSeconds}s ago`;
  }
  if (diffSeconds < 3600) {
    return `${Math.floor(diffSeconds / 60)}m ago`;
  }
  return `${Math.floor(diffSeconds / 3600)}h ago`;
}

function renderAuditLog(logs = []) {
  if (!logs.length) {
    return '<div class="detail-empty-inline">No audit activity yet.</div>';
  }

  const history = [...logs].sort((left, right) => normalizeTimestamp(right.timestamp) - normalizeTimestamp(left.timestamp));

  return `
    <div class="audit-list">
      ${history.map(log => `
        <div class="audit-item">
          <div class="timeline-text">${escapeHtml(formatAction(log))}</div>
          <div class="timeline-time">${escapeHtml(timeAgo(log.timestamp || Date.now()))}</div>
        </div>
      `).join("")}
    </div>
  `;
}

function renderEscalationBadge(isEscalating) {
  return `
    <span class="sequence-badge${isEscalating ? " is-alert" : ""}">
      ${isEscalating ? "Escalation detected" : "Stable sequence"}
    </span>
  `;
}

  function renderIndicators(indicators) {
    if (!indicators.length) {
      return "";
    }

  return `
    <div class="alert-indicators">
      ${indicators.map(indicator => `<span class="indicator-chip">${escapeHtml(indicator)}</span>`).join("")}
    </div>
    `;
  }

function renderExplanation(explanation = []) {
    if (!explanation.length) {
      return "";
    }

    return `
      <div class="alert-explanation">
        <h4>Why this alert was triggered</h4>
        <ul>
          ${explanation.map(item => `<li>${String(item || "")}</li>`).join("")}
        </ul>
      </div>
    `;
  }

  function formatMatchedFieldLabel(field) {
    const labels = {
      ip: "Source IP",
      user: "User",
      device: "Device",
      host: "Hostname",
      email: "Email",
      domain: "Domain"
    };
    return labels[field] || String(field || "").replaceAll("_", " ");
  }

  function renderCorrelationExplanationCard(alert) {
    const correlation = alert.correlation || {};
    const matchedFields = Array.isArray(correlation.matchedFields) ? correlation.matchedFields : [];
    const confidenceScore = Number(correlation.confidenceScore || 0);
    const confidencePercent = Math.max(0, Math.min(100, Math.round(confidenceScore * 100)));
    const relatedIp = normalizeAlertEnrichment(alert).ip || alert.sourceIp || alert.source_ip || "Unknown";
    const matchedFieldsMarkup = matchedFields.length
      ? `<div class="correlation-field-chips">
          ${matchedFields.map(field => `
            <span
              class="correlation-field-chip"
              title="Matched on ${escapeHtml(formatMatchedFieldLabel(field))}"
            >${escapeHtml(formatMatchedFieldLabel(field))}</span>
          `).join("")}
        </div>`
      : '<div class="detail-empty-inline">No matched fields recorded.</div>';
    return `
      <details class="detail-section detail-collapsible related-correlation-card">
        <summary class="detail-collapse-summary">
          <span class="related-alert-summary">
            <strong>${escapeHtml(alert.attackType)}</strong>
            <span class="panel-note">${escapeHtml(relatedIp)}</span>
          </span>
          <span
            class="correlation-confidence-pill"
            title="Confidence ${confidencePercent}% based on matched entities"
          >${confidencePercent}% confidence</span>
        </summary>
        <div class="correlation-explanation-grid">
          <div class="correlation-explanation-copy">
            <span class="ioc-pivot-title">Why this alert is related</span>
            <p>${escapeHtml(correlation.correlationReason || "Related by shared alert entities.")}</p>
          </div>
          <div class="correlation-explanation-copy">
            <span class="ioc-pivot-title">Matched fields</span>
            ${matchedFieldsMarkup}
          </div>
          <div class="correlation-explanation-copy">
            <span class="ioc-pivot-title">Confidence score</span>
            <div
              class="correlation-confidence-bar"
              role="progressbar"
              aria-valuemin="0"
              aria-valuemax="100"
              aria-valuenow="${confidencePercent}"
              title="Confidence score ${confidencePercent}%"
            >
              <span style="width:${confidencePercent}%"></span>
            </div>
          </div>
          <div class="correlation-explanation-copy">
            <span class="ioc-pivot-title">Rule source</span>
            <p title="${escapeHtml(correlation.ruleSource || "No rule source recorded")}">
              ${escapeHtml(String(correlation.ruleSource || "No rule source recorded").replaceAll("_", " "))}
            </p>
          </div>
        </div>
        <div class="correlation-explanation-actions">
          <button type="button" class="related-item related-item-open" data-alert-id="${escapeHtml(alert.id)}">
            Open related alert
          </button>
        </div>
      </details>
    `;
  }

function renderRankingList(node, entries, emptyLabel, formatter = value => String(value)) {
  node.innerHTML = "";

  if (!entries.length) {
    const item = document.createElement("li");
    item.className = "ranking-item";
    item.innerHTML = `
      <span class="ranking-label">${escapeHtml(emptyLabel)}</span>
      <span class="ranking-value mono">0</span>
    `;
    node.appendChild(item);
    return;
  }

  entries.forEach(([label, value]) => {
    const item = document.createElement("li");
    item.className = "ranking-item";
    item.innerHTML = `
      <span class="ranking-label">${escapeHtml(label)}</span>
      <span class="ranking-value mono">${escapeHtml(formatter(value))}</span>
    `;
    node.appendChild(item);
  });
}

function groupAlertsByIp(alerts) {
  const byIp = new Map();
  alerts.forEach(alert => {
    if (!byIp.has(alert.sourceIp)) {
      byIp.set(alert.sourceIp, []);
    }
    byIp.get(alert.sourceIp).push(alert);
  });
  byIp.forEach(list => {
    list.sort((left, right) => normalizeTimestamp(left.timestamp) - normalizeTimestamp(right.timestamp));
  });
  return byIp;
}

function summarizeAttackTypes(alerts) {
  return [...new Set(alerts.map(alert => alert.attackType))];
}

function detectEscalationPattern(alerts) {
  const orderedAlerts = [...alerts].sort((left, right) => normalizeTimestamp(left.timestamp) - normalizeTimestamp(right.timestamp));
  const attackTypes = summarizeAttackTypes(orderedAlerts);
  let severityEscalated = false;
  let attackTypeChanged = false;

  for (let index = 1; index < orderedAlerts.length; index += 1) {
    const previousAlert = orderedAlerts[index - 1];
    const nextAlert = orderedAlerts[index];
    if (nextAlert.attackType !== previousAlert.attackType) {
      attackTypeChanged = true;
    }
    if (getSeverityWeight(nextAlert.severity) > getSeverityWeight(previousAlert.severity)) {
      severityEscalated = true;
    }
  }

  return {
    attackTypes,
    isEscalating: orderedAlerts.length > 1 && (attackTypes.length > 1 || severityEscalated || attackTypeChanged),
    severityEscalated
  };
}

function renderSequenceTimeline(alerts, emptyLabel) {
  if (!alerts.length) {
    return `<div class="detail-empty-inline">${escapeHtml(emptyLabel)}</div>`;
  }

  return `
    <div class="sequence-list">
      ${alerts.map(alert => `
        <div class="sequence-item">
          <span class="sequence-time mono">${escapeHtml(formatTimestamp(alert.timestamp))}</span>
          <div class="sequence-copy">
            <div class="sequence-title-row">
              <strong>${escapeHtml(alert.attackType)}</strong>
              <div class="sequence-badges">
                ${renderSeverityBadge(alert.severity)}
                ${alert.isHoneypot ? '<span class="honeypot-flag">High confidence threat</span>' : ""}
              </div>
            </div>
            <span class="sequence-meta">${escapeHtml(alert.country)} · ${escapeHtml(alert.sourceIp)}</span>
          </div>
        </div>
      `).join("")}
    </div>
  `;
}

function mapSequenceEvents(sequence, selectedAlert) {
  if (!sequence?.events?.length) {
    return [];
  }

  return sequence.events.map(entry => ({
    attackType: entry.rule || "alert",
    severity: entry.severity || "medium",
    timestamp: entry.timestamp || selectedAlert.timestamp,
    country: selectedAlert.country,
    sourceIp: selectedAlert.sourceIp,
    isHoneypot: entry.rule === "honeypot_access"
  }));
}

export function createStatsPanel(nodes) {
  const feedNodes = Array.isArray(nodes.eventFeedNode) ? nodes.eventFeedNode.filter(Boolean) : [nodes.eventFeedNode].filter(Boolean);
  const feedCountNodes = Array.isArray(nodes.feedCountNode) ? nodes.feedCountNode.filter(Boolean) : [nodes.feedCountNode].filter(Boolean);
  const alerts = new Map();
  const state = {
    alerts: [],
    auditLogs: [],
    selectedAlertId: null,
    lastRenderHash: null
  };
  let nowProvider = () => Date.now();

  function getCurrentTime() {
    return nowProvider();
  }
  let lastRenderedAlertId = null;
  let activityChart = null;
  let filters = {
    severity: "all",
    ip: "",
    country: "",
    status: "all",
    attackType: "all",
    timeRange: "1m",
    sortBy: "time_desc"
  };

  function getAllAlerts() {
    return state.alerts;
  }

  function getTimeRangeMs() {
    const mapping = {
      "1m": 60_000,
      "1h": 3_600_000,
      "24h": 86_400_000
    };
    return mapping[filters.timeRange] || mapping["1m"];
  }

  function getFilteredAlerts() {
    const now = getCurrentTime();
    const earliestTimestamp = now - getTimeRangeMs();
    const explicitLifecycleFilter = filters.status !== "all";

    const filteredAlerts = getAllAlerts().filter(alert => {
      const lifecycle = normalizeAlertLifecycle(alert);
      if (!explicitLifecycleFilter && !isAlertEligibleForTriage(alert)) {
        return false;
      }
      const timestamp = normalizeTimestamp(alert.timestamp);
      if (timestamp < earliestTimestamp) {
        return false;
      }
      if (filters.severity !== "all" && alert.severity !== filters.severity) {
        return false;
      }
      if (filters.ip && !alert.sourceIp.toLowerCase().includes(filters.ip)) {
        return false;
      }
      if (filters.country && !String(alert.country || "").toLowerCase().includes(filters.country)) {
        return false;
      }
      if (explicitLifecycleFilter && lifecycle !== filters.status) {
        return false;
      }
      if (filters.attackType !== "all" && alert.attackType !== filters.attackType) {
        return false;
      }
      return true;
    });

    return filteredAlerts.sort((left, right) => {
      switch (filters.sortBy) {
        case "severity_desc":
          return getSeverityWeight(right.severity) - getSeverityWeight(left.severity)
            || normalizeTimestamp(right.timestamp) - normalizeTimestamp(left.timestamp);
        case "ip_asc":
          return String(left.sourceIp || "").localeCompare(String(right.sourceIp || ""))
            || normalizeTimestamp(right.timestamp) - normalizeTimestamp(left.timestamp);
        case "country_asc":
          return String(left.country || "").localeCompare(String(right.country || ""))
            || normalizeTimestamp(right.timestamp) - normalizeTimestamp(left.timestamp);
        case "status_asc":
          return String(normalizeAlertLifecycle(left) || "new").localeCompare(String(normalizeAlertLifecycle(right) || "new"))
            || normalizeTimestamp(right.timestamp) - normalizeTimestamp(left.timestamp);
        case "urgency_desc":
          return getLiveSlaState(right, now).urgencyScore - getLiveSlaState(left, now).urgencyScore
            || normalizeTimestamp(right.timestamp) - normalizeTimestamp(left.timestamp);
        case "attack_type_asc":
          return String(left.attackType || "").localeCompare(String(right.attackType || ""))
            || normalizeTimestamp(right.timestamp) - normalizeTimestamp(left.timestamp);
        case "time_desc":
        default:
          return normalizeTimestamp(right.timestamp) - normalizeTimestamp(left.timestamp);
      }
    });
  }

function buildChartColors(chart, buckets) {
    const chartArea = chart.chartArea;
    const context = chart.ctx;

    if (!chartArea) {
      return {
        backgrounds: buckets.map(() => hexToRgba(getThemeValue("--chart-low", "#0f62fe"), 0.75)),
        hoverBackgrounds: buckets.map(() => hexToRgba(getThemeValue("--chart-low", "#0f62fe"), 1))
      };
    }

    const backgrounds = buckets.map(bucket => buildBarGradient(context, chartArea, getBarColor(bucket.count)));
    const hoverBackgrounds = buckets.map(bucket => {
      const intensity = getBarColor(bucket.count);
      const palette = {
        low: getThemeValue("--chart-low", "#0f62fe"),
        medium: getThemeValue("--chart-medium", "#facc15"),
        high: getThemeValue("--chart-high", "#f97316")
      };
      return hexToRgba(palette[intensity] || palette.low, 1);
    });

    return { backgrounds, hoverBackgrounds };
  }

  function ensureActivityChart() {
    if (activityChart || !window.Chart || !nodes.timelineCanvas) {
      return activityChart;
    }

    activityChart = new window.Chart(nodes.timelineCanvas, {
      type: "bar",
      data: {
        labels: [],
        datasets: [
          {
            label: "Alerts per 5-second bucket",
            data: [],
            backgroundColor: [],
            hoverBackgroundColor: [],
            borderWidth: 0,
            hoverBorderWidth: 0,
            borderRadius: 10,
            borderSkipped: false,
            barPercentage: 0.82,
            categoryPercentage: 0.82
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: {
          duration: 380,
          easing: "easeOutCubic"
        },
        interaction: {
          mode: "index",
          intersect: false
        },
        plugins: {
          legend: {
            display: false
          },
          tooltip: {
            displayColors: false,
            backgroundColor: getThemeValue("--chart-tooltip-bg", "rgba(15, 23, 42, 0.92)"),
            titleColor: getThemeValue("--chart-tooltip-text", "#f8fafc"),
            bodyColor: getThemeValue("--chart-tooltip-text", "#f8fafc"),
            borderColor: getThemeValue("--chart-tooltip-border", "rgba(148, 163, 184, 0.24)"),
            borderWidth: 1,
            padding: 12,
            callbacks: {
              label(context) {
                const value = context.raw ?? 0;
                const unit = value === 1 ? "alert" : "alerts";
                return `${value} ${unit} at ${context.label}`;
              }
            }
          }
        },
        scales: {
          x: {
            grid: {
              color: getThemeValue("--chart-grid", "rgba(94, 114, 136, 0.08)"),
              drawBorder: false,
              tickLength: 0
            },
            ticks: {
              color: getThemeValue("--chart-axis-text", "#5e7288"),
              maxRotation: 0,
              autoSkip: true
            },
            title: {
              display: true,
              text: "Time (last 60s)",
              color: getThemeValue("--chart-axis-title", "#5e7288"),
              font: {
                size: 12,
                weight: "600"
              }
            }
          },
          y: {
            beginAtZero: true,
            ticks: {
              precision: 0,
              color: getThemeValue("--chart-axis-text", "#5e7288")
            },
            grid: {
              color: getThemeValue("--chart-grid", "rgba(94, 114, 136, 0.1)"),
              drawBorder: false
            },
            title: {
              display: true,
              text: "Number of attacks",
              color: getThemeValue("--chart-axis-title", "#5e7288"),
              font: {
                size: 12,
                weight: "600"
              }
            }
          }
        }
      }
    });

    return activityChart;
  }

  function renderTimeline(filteredAlerts, now = getCurrentTime()) {
    const chart = ensureActivityChart();
    if (!chart) {
      return;
    }

    const buckets = buildTimelineBuckets(now);
    filteredAlerts.forEach(alert => {
      const timestamp = normalizeTimestamp(alert.timestamp);
      if (timestamp < now - 60_000 || timestamp > now) {
        return;
      }

      const bucketIndex = buckets.findIndex(bucket => timestamp >= bucket.start && timestamp < bucket.end);
      if (bucketIndex >= 0) {
        buckets[bucketIndex].count += 1;
      }
    });

    chart.data.labels = buckets.map(bucket => bucket.label);
    chart.data.datasets[0].data = buckets.map(bucket => bucket.count);
    const { backgrounds, hoverBackgrounds } = buildChartColors(chart, buckets);
    chart.data.datasets[0].backgroundColor = backgrounds;
    chart.data.datasets[0].hoverBackgroundColor = hoverBackgrounds;
    chart.update();
  }

  function renderHeatmap(filteredAlerts, now = getCurrentTime()) {
    if (!nodes.heatmapNode) {
      return;
    }

    const buckets = buildHeatmapBuckets(filteredAlerts, now);
    nodes.heatmapNode.innerHTML = buckets.map(value => {
      const opacity = Math.min(Math.max(value / 5, 0.14), 1);
      const emptyClass = value === 0 ? " is-empty" : "";
      return `<div class="heat-cell${emptyClass}" style="opacity:${opacity}" title="${escapeHtml(String(value))} alerts"></div>`;
    }).join("");
  }

  function renderFilters() {
    const allAlerts = getAllAlerts();
    const attackTypes = [...new Set(allAlerts.map(alert => alert.attackType))].sort();

    if (nodes.filterAttackTypeNode) {
      nodes.filterAttackTypeNode.innerHTML = '<option value="all">All attack types</option>';
    }
    attackTypes.forEach(attackType => {
      if (!nodes.filterAttackTypeNode) {
        return;
      }
      const option = document.createElement("option");
      option.value = attackType;
      option.textContent = attackType;
      nodes.filterAttackTypeNode.appendChild(option);
    });
    if (nodes.filterAttackTypeNode) {
      nodes.filterAttackTypeNode.value = filters.attackType;
    }
    if (nodes.filterStatusNode) {
      nodes.filterStatusNode.value = filters.status;
    }
    if (nodes.filterSortNode) {
      nodes.filterSortNode.value = filters.sortBy;
    }
  }

  function selectAlert(id, options = {}) {
    const {
      notifySelection = true,
    } = options;
    const alertId = String(id || "");
    state.selectedAlertId = alertId;
    setSelectedAlertId(alertId);
    const alert = state.alerts.find(entry => entry.id === alertId) || null;
    renderAlertDetails(alert);
    renderAlertsList(getFilteredAlerts());
    if (alert) {
      window.__dashboardOnAlertSelected?.(alertId);
      if (notifySelection) {
        window.__dashboardOnSelectAlert?.(alertId);
      }
    }
    return alert;
  }

  function renderAlertsList(filteredAlerts) {
    feedNodes.forEach(node => {
      node.innerHTML = "";
    });
    const currentUser = getCurrentDashboardUser();

    if (!filteredAlerts.length) {
      feedNodes.forEach(node => {
        const emptyState = document.createElement("div");
        emptyState.className = "feed-empty";
        emptyState.textContent = "No alerts match the current filters. Try widening the time range or clearing a filter.";
        node.appendChild(emptyState);
      });
      feedCountNodes.forEach(node => {
        node.textContent = "0 matching alerts";
      });
      return;
    }

    filteredAlerts.forEach((alert, index) => {
      feedNodes.forEach(node => {
        const item = document.createElement("div");
        const isSelected = state.selectedAlertId === alert.id;
        item.dataset.alertId = alert.id;
        item.setAttribute("role", "button");
        item.tabIndex = 0;
        item.className = `feed-item feed-item-button severity-border-${alert.severity}${isSelected ? " is-selected" : ""}${alert.analyst && alert.analyst === currentUser?.username ? " my-alert" : ""}${index < 3 ? " priority-alert" : ""}`;
        const relatedCount = getAllAlerts().filter(candidate => candidate.id !== alert.id && candidate.sourceIp === alert.sourceIp).length;
        const liveSla = getLiveSlaState(alert, getCurrentTime());
        const liveAckTimer = liveSla.timeToAck != null
          ? formatDuration(liveSla.timeToAck)
          : formatDuration(liveSla.ackElapsed);
        item.innerHTML = `
          <div class="feed-row">
            <span class="feed-label-group">
              <span class="feed-label">${escapeHtml(alert.attackType)}</span>
              ${renderSeverityBadge(alert.severity)}
              ${alert.isHoneypot ? '<span class="honeypot-flag">High confidence threat</span>' : ""}
            </span>
            <span class="feed-country">${escapeHtml(alert.country)}</span>
          </div>
          <div class="feed-row">
            <span class="feed-meta">${escapeHtml(formatTimestamp(alert.timestamp))}</span>
            <span class="feed-ip">${escapeHtml(alert.sourceIp)}</span>
          </div>
            <div class="feed-row">
              <span class="feed-meta">${renderOwnerBadge(alert.analyst)}</span>
            <span class="feed-meta">
                ${renderWatchlistBadge(alert)}
                ${renderOverdueBadge(alert)}
                ${isAdminUser() ? renderLockBadge(alert.lockedBy) : ""}
              </span>
            </div>
          <div class="feed-row">
            <span class="feed-meta">Ack ${escapeHtml(liveAckTimer)}</span>
            <span class="feed-meta">Urgency ${escapeHtml(String(Math.round(liveSla.urgencyScore || 0)))}</span>
          </div>
          ${renderIndicators(alert.indicators)}
          ${isSelected ? `
          <div class="feed-triage-panel" aria-hidden="false">
            <div class="feed-triage-summary">
              <span class="feed-meta">Risk ${escapeHtml(String(alert.riskScore || 0))}</span>
              <span class="feed-meta">${escapeHtml(relatedCount ? `${relatedCount} related alerts` : "No related alerts")}</span>
            </div>
            <div class="feed-row feed-row-actions">
              <span class="feed-shortcut-hint">C Pick up Case · F False Positive</span>
              <span class="feed-action-group">
                <button type="button" class="button button-primary button-compact" data-alert-action="create-case" data-alert-id="${escapeHtml(alert.id)}">Pick up Case</button>
                <button type="button" class="button button-secondary button-compact" data-alert-action="false-positive" data-alert-id="${escapeHtml(alert.id)}">False Positive</button>
              </span>
            </div>
          </div>` : ""}
        `;
        const openAlert = () => {
          selectAlert(alert.id);
        };
        item.addEventListener("click", openAlert);
        item.addEventListener("keydown", event => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            openAlert();
          }
        });
        item.querySelectorAll("[data-alert-action]").forEach(button => {
          button.addEventListener("click", event => {
            event.stopPropagation();
            openAlert();
            const action = button.getAttribute("data-alert-action");
            if (action === "create-case") {
              window.createCaseFromAlert?.(alert.id);
              return;
            }
            if (action === "false-positive") {
              window.markFalsePositive?.(alert.id);
            }
          });
        });
        node.appendChild(item);
      });
    });
    feedCountNodes.forEach(node => {
      node.textContent = `${filteredAlerts.length} matching alerts`;
    });
  }

  function getSelectedAlert(filteredAlerts) {
    const allAlerts = getAllAlerts();
    return allAlerts.find(alert => alert.id === state.selectedAlertId) || filteredAlerts[0] || null;
  }

  function renderAlertDetails(selectedAlert) {
    if (!selectedAlert) {
      lastRenderedAlertId = null;
      nodes.detailStatusNode.textContent = "Select an alert";
      nodes.alertDetailNode.className = "detail-empty";
      nodes.alertDetailNode.textContent = "Choose an alert to inspect its context and related activity.";
      return;
    }

    if (lastRenderedAlertId === selectedAlert.id) {
      return;
    }

    lastRenderedAlertId = selectedAlert.id;

    const allAlerts = getAllAlerts();

    state.selectedAlertId = selectedAlert.id;
    setSelectedAlertId(selectedAlert.id);
    nodes.detailStatusNode.textContent = selectedAlert.attackType;
    const alertsForIp = allAlerts
      .filter(alert => alert.sourceIp === selectedAlert.sourceIp)
      .sort((left, right) => normalizeTimestamp(left.timestamp) - normalizeTimestamp(right.timestamp));
    const attackTypesForIp = summarizeAttackTypes(alertsForIp);
    const escalation = detectEscalationPattern(alertsForIp);
    const previousTimeline = alertsForIp
      .filter(alert => alert.id !== selectedAlert.id)
      .slice(-8);
    const coordinatedSequence = mapSequenceEvents(selectedAlert.sequence, selectedAlert);

    const relatedAlerts = correlateRelatedAlerts(selectedAlert, allAlerts).slice(0, 6);
    const enrichment = normalizeAlertEnrichment(selectedAlert);
    const reputation = getIpReputation(selectedAlert);
    const networkMarkup = renderEnrichmentGroup("Network", [
      { label: "IP", value: enrichment.ip, iocType: "ip" },
      { label: "Destination IP", value: enrichment.destinationIp, iocType: "ip" },
      { label: "Country", value: enrichment.country },
      { label: "Region", value: enrichment.region },
      { label: "City", value: enrichment.city },
      { label: "ASN", value: enrichment.asn },
      { label: "Provider", value: enrichment.isp },
      { label: "Location", value: enrichment.location },
      { label: "Reputation", value: reputation }
    ]);
    const identityMarkup = renderEnrichmentGroup("Identity", [
      { label: "Username", value: enrichment.username, iocType: "username" },
      { label: "Account", value: enrichment.account, iocType: "username" },
      { label: "Email", value: enrichment.email, iocType: "email" },
      { label: "Sender", value: enrichment.senderEmail, iocType: "email" },
      { label: "Recipient", value: enrichment.recipientEmail, iocType: "email" },
      { label: "User Email", value: enrichment.userEmail, iocType: "email" },
      { label: "Email Domain", value: enrichment.domain, iocType: "domain" },
      { label: "Entity", value: enrichment.relatedEntity }
    ]);
    const deviceMarkup = renderEnrichmentGroup("Device", [
      { label: "Device", value: enrichment.device },
      { label: "Hostname", value: enrichment.hostname, iocType: "hostname" },
      { label: "OS", value: enrichment.deviceOs },
      { label: "Browser", value: enrichment.browser }
    ]);
    const threatMarkup = renderEnrichmentGroup("Threat Context", [
      { label: "Attack Type", value: enrichment.attackType },
      { label: "Severity", value: enrichment.severity },
      { label: "Risk Score", value: enrichment.riskScore ? String(enrichment.riskScore) : "" },
      { label: "Threat Level", value: enrichment.threatLevel },
      { label: "Lifecycle", value: getAlertLifecycleLabel(selectedAlert.lifecycle || selectedAlert.status) },
      { label: "Linked Case", value: selectedAlert.mergedIntoCaseId || selectedAlert.case_id || "" }
    ]);

    const highestSeverityLabel = escapeHtml(getSeverityLabel(alertsForIp.reduce((highest, alert) =>
      getSeverityWeight(alert.severity) > getSeverityWeight(highest) ? alert.severity : highest
    , selectedAlert.severity)));
    const entityContext = buildEntityContextForAlert(selectedAlert, getAllAlerts());
    const now = getCurrentTime();
    const relatedAlertsMarkup = relatedAlerts.length
      ? `<div class="related-list">${relatedAlerts.map(renderCorrelationExplanationCard).join("")}</div>`
      : '<div class="detail-empty-inline">No related alerts matched by IP, user, device, email, or domain.</div>';
    const coordinatedSequenceMarkup = selectedAlert.sequence?.type && selectedAlert.sequence.type !== "single"
      ? `<details class="detail-section detail-collapsible">
          <summary class="detail-collapse-summary">
            <strong>Attack Chain</strong>
            ${renderSequenceTypeBadge(selectedAlert.sequence?.type)}
          </summary>
          ${renderSequenceTimeline(coordinatedSequence, "No multi-stage attack chain is attached to this alert.")}
        </details>`
      : "";

    nodes.alertDetailNode.className = "detail-panel";
    nodes.alertDetailNode.innerHTML = buildAlertDetailMarkup({
      alert: {
        ...selectedAlert,
        attackType: escapeHtml(selectedAlert.attackType),
      },
      alertsForIp,
      attackTypesForIp: attackTypesForIp.map(type => escapeHtml(type)),
      escalationBadge: renderEscalationBadge(escalation.isEscalating),
      highestSeverityLabel,
      coordinatedSequenceMarkup,
      previousTimelineMarkup: renderSequenceTimeline(
        coordinatedSequence.length ? coordinatedSequence : previousTimeline,
        "No previous activity for this IP in the current dataset."
      ),
      relatedAlertsMarkup,
      summaryBadgesMarkup: `
        ${renderSequenceTypeBadge(selectedAlert.sequence?.type)}
        ${renderSeverityBadge(selectedAlert.severity)}
        ${renderAlertStatus(selectedAlert.status)}
        ${renderWatchlistBadge(selectedAlert)}
        ${renderOverdueBadge(selectedAlert, now)}
        ${renderFalsePositiveBadge(selectedAlert.falsePositive)}
        ${renderBlockedBadge(selectedAlert.isBlocked)}
        ${isAdminUser() ? renderLockBadge(selectedAlert.lockedBy) : ""}
        ${isAdminUser() ? renderSlaBadge(selectedAlert.createdAt) : ""}
      `,
      detailGridMarkup: `
        <span><strong>Time:</strong> ${escapeHtml(formatDateTime(selectedAlert.timestamp))}</span>
        <span><strong>Country:</strong> ${escapeHtml(selectedAlert.country)}</span>
        <span><strong>IP:</strong> ${renderHuntPivot("ip", selectedAlert.sourceIp, selectedAlert.sourceIp)}</span>
        <span><strong>Geo:</strong> ${escapeHtml(
          selectedAlert.sourceLat != null && selectedAlert.sourceLon != null
            ? `${selectedAlert.sourceLat.toFixed(3)}, ${selectedAlert.sourceLon.toFixed(3)}`
            : "Unavailable"
        )}</span>
        <span><strong>User:</strong> ${renderHuntPivot("user", selectedAlert.userId, selectedAlert.userId)}</span>
        <span><strong>Attack:</strong> ${renderHuntPivot("attack", selectedAlert.attackType, selectedAlert.attackType)}</span>
        <span><strong>Risk Score:</strong> ${renderRiskScore(selectedAlert.riskScore || 0)}</span>
        <span><strong>Threat Level:</strong> ${renderThreatLevel(selectedAlert.threatLevel)}</span>
        <span><strong>Incident Status:</strong> ${renderAlertStatus(selectedAlert.status)}</span>
        <span><strong>Assigned To:</strong> ${escapeHtml(selectedAlert.assignedTo || "None")}</span>
        <span><strong>Linked Case:</strong> ${escapeHtml(selectedAlert.mergedIntoCaseId || selectedAlert.case_id || "None")}</span>
        <span><strong>Watchlist Hits:</strong> ${escapeHtml(String(selectedAlert.watchlistHitsCount || 0))}</span>
        ${renderSlaSummary(selectedAlert, now)}
        <span><strong>Urgency:</strong> ${escapeHtml(String(Math.round(selectedAlert.urgencyScore || 0)))}</span>
      `,
      indicatorsMarkup: renderIndicators(selectedAlert.indicators),
      analystMarkup: renderAnalyst(selectedAlert.analyst),
      explanationMarkup: renderExplanation(
        (selectedAlert.explanation || []).map(item => highlightIocsInText(item, selectedAlert))
      ),
      riskEvolutionMarkup: renderRiskEvolution(selectedAlert.riskHistory),
      mitreMarkup: renderMitre(selectedAlert.mitre, selectedAlert.attackType),
      enrichmentMarkup: `${networkMarkup}${identityMarkup}${deviceMarkup}${threatMarkup}`,
      entityContextMarkup: renderEntityContextPanels(entityContext),
      iocMarkup: renderIocSection(selectedAlert),
      pivotMarkup: "",
      sourceIp: escapeHtml(selectedAlert.sourceIp),
      rawJson: escapeHtml(JSON.stringify(selectedAlert.raw, null, 2)),
    });

    nodes.alertDetailNode.querySelectorAll("[data-entity-type][data-entity-key]").forEach(button => {
      button.addEventListener("click", () => {
        window.openEntityProfile?.(button.getAttribute("data-entity-type"), button.getAttribute("data-entity-key"));
      });
    });
    nodes.alertDetailNode.querySelectorAll("[data-hunt-query-field][data-hunt-query-value]").forEach(button => {
      button.addEventListener("click", event => {
        event.stopPropagation();
        const field = button.getAttribute("data-hunt-query-field");
        const value = button.getAttribute("data-hunt-query-value");
        window.launchHuntQuery?.(`${field}:${value}`);
      });
    });
    nodes.alertDetailNode.querySelectorAll("[data-alert-id]").forEach(button => {
      button.addEventListener("click", () => {
        selectAlert(button.getAttribute("data-alert-id"));
      });
    });
    nodes.alertDetailNode.querySelectorAll("[data-watchlist-action]").forEach(button => {
      button.addEventListener("click", event => {
        event.stopPropagation();
        const action = button.getAttribute("data-watchlist-action");
        const type = button.getAttribute("data-watchlist-type");
        const value = button.getAttribute("data-watchlist-value");
        if (action === "remove") {
          window.removeFromWatchlist?.(type, value);
          return;
        }
        window.addToWatchlist?.(type, value);
      });
    });
  }

  function renderCorrelation(filteredAlerts) {
    if (!nodes.correlationViewNode) {
      return;
    }
    nodes.correlationViewNode.innerHTML = "";
    const byIp = groupAlertsByIp(filteredAlerts);

    const rows = [...byIp.entries()]
      .map(([ip, alertsForIp]) => {
        const attackTypes = summarizeAttackTypes(alertsForIp);
        const escalation = detectEscalationPattern(alertsForIp);
        const highestSeverity = alertsForIp.reduce((highest, alert) =>
          getSeverityWeight(alert.severity) > getSeverityWeight(highest) ? alert.severity : highest
        , alertsForIp[0]?.severity || "medium");
        const sequenceAlert = alertsForIp.find(alert => alert.sequence?.type && alert.sequence.type !== "single") || null;
        return [ip, { alerts: alertsForIp, attackTypes, escalation, highestSeverity, sequenceAlert }];
      })
      .sort((left, right) =>
        right[1].attackTypes.length - left[1].attackTypes.length ||
        right[1].alerts.length - left[1].alerts.length
      )
      .slice(0, 8);

    if (!rows.length) {
      nodes.correlationViewNode.className = "detail-empty";
      nodes.correlationViewNode.textContent = "Correlation appears here when multiple alerts share the same source.";
      return;
    }

    nodes.correlationViewNode.className = "correlation-list";
    rows.forEach(([ip, entry]) => {
      const entityContext = window.__dashboardGetEntityContext?.(ip) || {};
      const entityInvestigation = entityContext.investigation || null;
      const entityCase = entityContext.caseRecord || null;
      const lastSeenAlert = [...entry.alerts].sort((left, right) => normalizeTimestamp(right.timestamp) - normalizeTimestamp(left.timestamp))[0] || null;
      const item = document.createElement("article");
      item.className = `correlation-item${workbenchState.selectedEntityKey === ip ? " is-selected" : ""}`;
      item.tabIndex = 0;
      item.setAttribute("role", "button");
      item.setAttribute("aria-label", `Load correlated alerts for ${ip}`);
      const sequencePreview = entry.sequenceAlert
        ? mapSequenceEvents(entry.sequenceAlert.sequence, entry.sequenceAlert)
        : entry.alerts.slice(-5);
      const primaryAlert = [...entry.alerts].sort(sortAlertsByPriority)[0] || entry.alerts[0] || null;
      item.innerHTML = `
        <div class="correlation-row">
          <strong>${escapeHtml(ip)}</strong>
          <div class="correlation-badges">
            ${renderSequenceTypeBadge(entry.sequenceAlert?.sequence?.type)}
            ${renderEscalationBadge(entry.escalation.isEscalating)}
            ${renderSeverityBadge(entry.highestSeverity)}
          </div>
        </div>
        <div class="entity-metrics">
          <div class="entity-metric">
            <span class="entity-metric-label">Alerts</span>
            <strong>${entry.alerts.length}</strong>
          </div>
          <div class="entity-metric">
            <span class="entity-metric-label">Attack types</span>
            <strong>${entry.attackTypes.length}</strong>
          </div>
          <div class="entity-metric">
            <span class="entity-metric-label">Highest severity</span>
            <strong>${escapeHtml(getSeverityLabel(entry.highestSeverity))}</strong>
          </div>
          <div class="entity-metric">
            <span class="entity-metric-label">Last seen</span>
            <strong>${escapeHtml(formatDateTime(lastSeenAlert?.timestamp || Date.now()))}</strong>
          </div>
        </div>
        <div class="correlation-row correlation-copy">
          <span>${entry.attackTypes.join(", ") || "No attack types available"}</span>
          <span class="entity-status-row">
            ${entityInvestigation ? `<span class="record-badge">${escapeHtml(String(entityInvestigation.status || "investigating").toUpperCase())} INVESTIGATION</span>` : '<span class="panel-note">No investigation</span>'}
            ${entityCase ? `<span class="record-badge">${escapeHtml(String(entityCase.status || "open").toUpperCase())} CASE</span>` : '<span class="panel-note">No case</span>'}
          </span>
        </div>
        <div class="correlation-sequence">
          <strong>Sequence</strong>
          ${renderSequenceTimeline(sequencePreview, "No timeline available.")}
        </div>
        <div class="detail-actions correlation-actions">
          <button
            type="button"
            class="button button-secondary action-btn"
            data-correlation-action="investigate"
            data-alert-id="${escapeHtml(primaryAlert?.id || "")}"
          >
            Investigate
          </button>
          <button
            type="button"
            class="button button-secondary action-btn"
            data-correlation-action="create-case"
            data-alert-id="${escapeHtml(primaryAlert?.id || "")}"
          >
            Create Case
          </button>
        </div>
      `;
      const focusCorrelation = () => {
        setSelectedEntityKey(ip);
        filters = {
          ...filters,
          severity: "all",
          ip: String(ip || "").toLowerCase(),
          country: "",
          attackType: "all"
        };

        if (nodes.filterSeverityNode) {
          nodes.filterSeverityNode.value = filters.severity;
        }
        if (nodes.filterIpNode) {
          nodes.filterIpNode.value = ip;
        }
        if (nodes.filterCountryNode) {
          nodes.filterCountryNode.value = filters.country;
        }
        if (nodes.filterAttackTypeNode) {
          nodes.filterAttackTypeNode.value = filters.attackType;
        }

        renderPartial({
          filters: true,
          overview: false,
          activity: false,
          alertsList: true,
          details: true,
          correlation: true,
          audit: false
        });

        const relatedAlerts = getFilteredAlerts().filter(alert => alert.sourceIp === ip);
        const firstAlert = relatedAlerts[0] || primaryAlert;
        if (firstAlert) {
          selectAlert(firstAlert.id, { notifySelection: false });
        }
      };

      item.addEventListener("click", event => {
        if (event.target.closest("[data-correlation-action]")) {
          return;
        }
        focusCorrelation();
      });
      item.addEventListener("keydown", event => {
        if (event.key !== "Enter" && event.key !== " ") {
          return;
        }
        event.preventDefault();
        focusCorrelation();
      });
      item.querySelectorAll("[data-correlation-action]").forEach(button => {
        button.addEventListener("click", event => {
          event.stopPropagation();
          const alertId = button.getAttribute("data-alert-id");
          if (!alertId) {
            return;
          }
          if (button.getAttribute("data-correlation-action") === "investigate") {
            window.investigateAlertContext?.(alertId);
            return;
          }
          focusCorrelation();
          window.createCaseFromAlert?.(alertId);
        });
      });
      nodes.correlationViewNode.appendChild(item);
    });
  }

  function renderAuditPanel() {
    if (!nodes.auditPanelNode) {
      return;
    }
    nodes.auditPanelNode.innerHTML = renderAuditLog(state.auditLogs);
  }

  function renderAnalystsPanel(filteredAlerts = getFilteredAlerts()) {
    if (!nodes.analystListNode) {
      return;
    }

    const counts = new Map();
    filteredAlerts.forEach(alert => {
      if (alert.analyst) {
        counts.set(alert.analyst, (counts.get(alert.analyst) || 0) + 1);
      }
    });

    if (!counts.size) {
      nodes.analystListNode.innerHTML = '<div class="detail-empty-inline">No active analysts yet.</div>';
      return;
    }

    nodes.analystListNode.innerHTML = [...counts.entries()]
      .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
      .map(([user, count]) => `
        <div class="analyst-row">
          <span>${escapeHtml(user)}</span>
          <span>${escapeHtml(String(count))} active</span>
        </div>
      `)
      .join("");
  }

  function renderOverview(filteredAlerts) {
    const now = getCurrentTime();
    const totalAttacks = filteredAlerts.length;
    const lastMinuteAlerts = filteredAlerts.filter(alert => now - normalizeTimestamp(alert.timestamp) <= 60_000);
    const uniqueIps = new Set(filteredAlerts.map(alert => alert.sourceIp));
    const countryCounts = new Map();
    const typeCounts = new Map();
    const severityCounts = new Map();
    let highSeverityCount = 0;
    let honeypotCount = 0;
    let honeypotLastTriggered = null;
    let slaEligibleCount = 0;
    let slaCompliantCount = 0;

    filteredAlerts.forEach(alert => {
      countryCounts.set(alert.country, (countryCounts.get(alert.country) || 0) + 1);
      typeCounts.set(alert.attackType, (typeCounts.get(alert.attackType) || 0) + 1);
      severityCounts.set(alert.severity, (severityCounts.get(alert.severity) || 0) + 1);
      if (alert.severity === "high" || alert.severity === "critical") {
        highSeverityCount += 1;
      }
      if (alert.isHoneypot && now - normalizeTimestamp(alert.timestamp) <= 600_000) {
        honeypotCount += 1;
        honeypotLastTriggered = Math.max(honeypotLastTriggered || 0, normalizeTimestamp(alert.timestamp));
      }
      if (alert.createdAt || alert.timestamp) {
        slaEligibleCount += 1;
        if (!getLiveSlaState(alert, now).overdue) {
          slaCompliantCount += 1;
        }
      }
    });

    const byIp = new Map();
    filteredAlerts.forEach(alert => {
      if (!byIp.has(alert.sourceIp)) {
        byIp.set(alert.sourceIp, new Set());
      }
      byIp.get(alert.sourceIp).add(alert.attackType);
    });

    let topCorrelated = "None";
    let topCorrelationCount = 0;
    byIp.forEach((attackTypes, ip) => {
      if (attackTypes.size > topCorrelationCount) {
        topCorrelationCount = attackTypes.size;
        topCorrelated = `${ip} (${attackTypes.size})`;
      }
    });

    nodes.totalAttacksNode.textContent = totalAttacks.toLocaleString();
    nodes.attacksPerMinuteNode.textContent = lastMinuteAlerts.length.toLocaleString();
    nodes.uniqueIpsNode.textContent = uniqueIps.size.toLocaleString();
    nodes.highSeverityPercentNode.textContent = totalAttacks ? `${Math.round((highSeverityCount / totalAttacks) * 100)}%` : "0%";
    nodes.honeypotTriggersNode.textContent = honeypotCount.toLocaleString();
    if (nodes.honeypotLastTriggeredNode) {
      nodes.honeypotLastTriggeredNode.textContent = honeypotLastTriggered
        ? `Last triggered ${formatTimestamp(honeypotLastTriggered)}`
        : "No recent trigger";
    }
    const slaCompliancePercent = slaEligibleCount ? Math.round((slaCompliantCount / slaEligibleCount) * 100) : 100;
    nodes.topCorrelatedIpNode.textContent = `${topCorrelated} · SLA ${slaCompliancePercent}%`;
    nodes.countryTotalNode.textContent = `${countryCounts.size} countries`;

    const topCountries = [...countryCounts.entries()].sort((left, right) => right[1] - left[1]).slice(0, 5);
    const topAttackTypes = [...typeCounts.entries()].sort((left, right) => right[1] - left[1]).slice(0, 5);
    const severityBreakdown = [...severityCounts.entries()]
      .sort((left, right) => getSeverityWeight(right[0]) - getSeverityWeight(left[0]) || right[1] - left[1]);
    const recentCriticalAlerts = [...filteredAlerts]
      .filter(alert => alert.severity === "critical" || alert.severity === "high")
      .sort((left, right) => normalizeTimestamp(right.timestamp) - normalizeTimestamp(left.timestamp))
      .slice(0, 5);
    renderRankingList(nodes.topCountriesNode, topCountries, "No country data");
    renderRankingList(nodes.topAttackTypesNode, topAttackTypes, "No attack data");
    renderRankingList(
      nodes.severityBreakdownNode,
      severityBreakdown.map(([severity, count]) => [getSeverityLabel(severity), count]),
      "No severity data"
    );
    if (nodes.recentCriticalAlertsNode) {
      nodes.recentCriticalAlertsNode.innerHTML = recentCriticalAlerts.length
        ? recentCriticalAlerts.map(alert => `
            <article class="feed-item feed-item-button recent-critical-alert severity-border-${escapeHtml(alert.severity)}" data-dashboard-alert-id="${escapeHtml(alert.id)}" role="button" tabindex="0">
              <div class="feed-row">
                <span class="feed-label-group">
                  <span class="feed-label">${escapeHtml(alert.attackType)}</span>
                  ${renderSeverityBadge(alert.severity)}
                </span>
                <span class="record-badge">${escapeHtml(String(alert.status || "open").toUpperCase())}</span>
              </div>
              <div class="feed-row">
                <span class="feed-ip">${escapeHtml(alert.sourceIp)}</span>
                <span class="feed-meta">${escapeHtml(formatTimestamp(alert.timestamp))}</span>
              </div>
            </article>
          `).join("")
        : '<div class="detail-empty-inline">No recent critical alerts.</div>';
      nodes.recentCriticalAlertsNode.querySelectorAll("[data-dashboard-alert-id]").forEach(item => {
        const openAlert = () => {
          window.openInvestigation?.(item.getAttribute("data-dashboard-alert-id"), { forceVisible: true });
        };
        item.addEventListener("click", openAlert);
        item.addEventListener("keydown", event => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            openAlert();
          }
        });
      });
    }
    if (nodes.watchlistPanelNode && nodes.watchlistStatusNode) {
      const entries = window.__dashboardGetWatchlist?.() || [];
      nodes.watchlistStatusNode.textContent = entries.length
        ? `${entries.length} entries tracked`
        : "No watchlist entries";
      nodes.watchlistPanelNode.innerHTML = entries.length
        ? entries.slice(0, 8).map(entry => `
            <article class="feed-item">
              <div class="feed-row">
                <span class="feed-label-group">
                  <span class="feed-label">${escapeHtml(entry.value)}</span>
                  <span class="record-badge">${escapeHtml(String(entry.type || "ioc").toUpperCase())}</span>
                </span>
                <span class="watchlist-hit-count">${escapeHtml(String(entry.hits_count || 0))} alerts</span>
              </div>
              <div class="feed-row">
                <span class="feed-meta">${escapeHtml(String(entry.cases_count || 0))} cases</span>
                <span class="feed-meta">${escapeHtml(entry.last_seen_at ? timeAgo(entry.last_seen_at) : "No recurrence yet")}</span>
              </div>
            </article>
          `).join("")
        : '<div class="detail-empty-inline">No watchlist entries yet.</div>';
    }
  }

  function renderOverviewSection(filteredAlerts) {
    renderOverview(filteredAlerts);
  }

  function renderTopCountries(filteredAlerts) {
    renderOverview(filteredAlerts);
  }

  function renderAttackTypes(filteredAlerts) {
    renderOverview(filteredAlerts);
  }

  function renderActivityChart(filteredAlerts) {
    renderTimeline(filteredAlerts);
    renderHeatmap(filteredAlerts);
  }

  function shouldUpdate(nextAlerts) {
    const nextSnapshot = JSON.stringify(nextAlerts);
    if (nextSnapshot === state.lastRenderHash) {
      return false;
    }
    state.lastRenderHash = nextSnapshot;
    return true;
  }

  function renderPartial(options = {}) {
    if (getUiState().isUserInteracting) {
      return;
    }
    const filteredAlerts = getFilteredAlerts();
    if (filteredAlerts.length && !filteredAlerts.some(alert => alert.id === state.selectedAlertId)) {
      state.selectedAlertId = filteredAlerts[0].id;
      setSelectedAlertId(state.selectedAlertId);
    }
    const selectedAlert = getSelectedAlert(filteredAlerts);

    if (options.filters !== false) {
      renderFilters();
    }
    if (options.overview !== false) {
      renderOverviewSection(filteredAlerts);
      renderTopCountries(filteredAlerts);
      renderAttackTypes(filteredAlerts);
      renderAnalystsPanel(filteredAlerts);
    }
    if (options.activity !== false) {
      renderActivityChart(filteredAlerts);
    }
    if (options.alertsList !== false) {
      renderAlertsList(filteredAlerts);
    }
    if (options.details !== false) {
      renderAlertDetails(selectedAlert);
    }
    if (options.correlation !== false && nodes.correlationViewNode) {
      renderCorrelation(filteredAlerts);
    }
    if (options.audit !== false) {
      renderAuditPanel();
    }
  }

  function render() {
    renderPartial();
  }

  function applyFilters() {
    filters = {
      severity: nodes.filterSeverityNode?.value || "all",
      ip: nodes.filterIpNode?.value.trim().toLowerCase() || "",
      country: nodes.filterCountryNode?.value.trim().toLowerCase() || "",
      status: nodes.filterStatusNode?.value || "all",
      attackType: nodes.filterAttackTypeNode?.value || "all",
      timeRange: nodes.filterTimeRangeNode?.value || "1m",
      sortBy: nodes.filterSortNode?.value || "time_desc"
    };
    render();
  }

  function setFilters(nextFilters = {}) {
    filters = {
      ...filters,
      ...nextFilters
    };
    if (nodes.filterSeverityNode) {
      nodes.filterSeverityNode.value = filters.severity;
    }
    if (nodes.filterIpNode) {
      nodes.filterIpNode.value = filters.ip;
    }
    if (nodes.filterCountryNode) {
      nodes.filterCountryNode.value = filters.country;
    }
    if (nodes.filterStatusNode) {
      nodes.filterStatusNode.value = filters.status;
    }
    if (nodes.filterAttackTypeNode) {
      nodes.filterAttackTypeNode.value = filters.attackType;
    }
    if (nodes.filterTimeRangeNode) {
      nodes.filterTimeRangeNode.value = filters.timeRange;
    }
    if (nodes.filterSortNode) {
      nodes.filterSortNode.value = filters.sortBy;
    }
    render();
  }

  function attachFilterListeners() {
    [
      nodes.filterSeverityNode,
      nodes.filterIpNode,
      nodes.filterCountryNode,
      nodes.filterStatusNode,
      nodes.filterAttackTypeNode,
      nodes.filterTimeRangeNode,
      nodes.filterSortNode
    ].forEach(node => {
      node?.addEventListener("input", applyFilters);
      node?.addEventListener("change", applyFilters);
    });
  }

  function upsertAlert(alert) {
    const normalizedAlert = normalizeStoredAlert(alert);
    alerts.set(normalizedAlert.id, normalizedAlert);
  }

  function setAlerts(nextAlerts) {
    if (!shouldUpdate(nextAlerts)) {
      return;
    }
    alerts.clear();
    nextAlerts.forEach(upsertAlert);
    state.alerts = [...alerts.values()].sort(sortAlertsByPriority);
    renderPartial();
  }

  function recordEvent(alert) {
    upsertAlert(alert);
    state.alerts = [...alerts.values()].sort(sortAlertsByPriority);
    renderPartial({
      overview: true,
      activity: true,
      alertsList: true,
      details: true,
      correlation: true,
      audit: false,
      filters: false
    });
  }

  function updateAlertOwnership(update) {
    const alertId = String(update.alert_id || "");
    const existingAlert = alerts.get(alertId);
    if (!existingAlert) {
      return;
    }

    const nextAlert = normalizeStoredAlert({
      ...existingAlert,
      assigned_to: update.assigned_to ?? existingAlert.assigned_to ?? existingAlert.analyst,
      analyst: update.assigned_to ?? existingAlert.analyst,
      status: update.status ?? existingAlert.status,
      disposition: update.disposition ?? existingAlert.disposition,
      merged_into_case_id: update.merged_into_case_id ?? existingAlert.mergedIntoCaseId ?? existingAlert.merged_into_case_id,
      updated_at: update.updated_at ?? existingAlert.updatedAt ?? existingAlert.updated_at,
      locked_by: update.locked_by ?? existingAlert.lockedBy ?? existingAlert.locked_by
    });

    alerts.set(alertId, nextAlert);
    state.alerts = [...alerts.values()].sort(sortAlertsByPriority);

    if (state.selectedAlertId === alertId) {
      lastRenderedAlertId = null;
      renderAlertDetails(nextAlert);
    }

    renderPartial({
      overview: true,
      activity: false,
      alertsList: true,
      details: false,
      correlation: true,
      audit: false,
      filters: false
    });
  }

  function getAlertById(id) {
    return alerts.get(String(id)) || null;
  }

  function getAlerts() {
    return [...state.alerts];
  }

  function getFilteredAlertsSnapshot() {
    return [...getFilteredAlerts()];
  }

  function reset() {
    alerts.clear();
    state.alerts = [];
    state.selectedAlertId = null;
    setSelectedAlertId(null);
    setSelectedEntityKey("");
    state.lastRenderHash = null;
    lastRenderedAlertId = null;
    renderPartial();
  }

  function setConnectionStatus({ label, tone }) {
    nodes.connectionNode.textContent = label;
    nodes.connectionNode.className = `status-value ${tone === "error" ? "is-error" : "is-live"}`;
  }

  function getSnapshot() {
    const filteredAlerts = getFilteredAlerts();
    const now = getCurrentTime();
    const slaEligibleAlerts = filteredAlerts.filter(alert => Boolean(alert.createdAt || alert.timestamp));
    const slaCompliantCount = slaEligibleAlerts.filter(alert => !getLiveSlaState(alert, now).overdue).length;
    return {
      totalAttacks: filteredAlerts.length,
      attacksPerMinute: filteredAlerts.filter(alert => now - normalizeTimestamp(alert.timestamp) <= 60_000).length,
      uniqueIps: new Set(filteredAlerts.map(alert => alert.sourceIp)).size,
      recentAlerts: filteredAlerts.slice(0, 12),
      slaCompliancePercent: slaEligibleAlerts.length ? Math.round((slaCompliantCount / slaEligibleAlerts.length) * 100) : 100
    };
  }

  function setAuditLogs(logs) {
    state.auditLogs = Array.isArray(logs) ? logs : [];
    renderAuditPanel();
  }

  function setNowProvider(provider) {
    nowProvider = typeof provider === "function" ? provider : () => Date.now();
    render();
  }

  attachFilterListeners();
  render();
  setInterval(render, 1000);

  return {
    setAlerts,
    recordEvent,
    reset,
    render,
    setConnectionStatus,
    getSnapshot,
    setAuditLogs,
    updateAlertOwnership,
    getAlertById,
    getAlerts,
    getFilteredAlerts: getFilteredAlertsSnapshot,
    selectAlert,
    setFilters,
    setNowProvider
  };
}
