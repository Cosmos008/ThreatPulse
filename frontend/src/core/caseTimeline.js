function safeString(value) {
  return String(value ?? "").trim();
}

function buildTimelineId(timestamp) {
  return `case-tl-${Math.random().toString(16).slice(2, 10)}-${Math.floor(timestamp)}`;
}

function formatStatusLabel(status) {
  const normalized = safeString(status).toLowerCase();
  const labels = {
    open: "Open",
    in_progress: "In Progress",
    contained: "Contained",
    resolved: "Resolved",
    closed: "Closed"
  };
  return labels[normalized] || (normalized ? normalized.replace(/_/g, " ").replace(/\b\w/g, letter => letter.toUpperCase()) : "Unknown");
}

function formatClosureReason(reason) {
  const normalized = safeString(reason).toLowerCase();
  const labels = {
    false_positive: "False Positive"
  };
  return labels[normalized] || (normalized ? normalized.replace(/_/g, " ").replace(/\b\w/g, letter => letter.toUpperCase()) : "Unknown");
}

export function buildCaseTimelineEvent({
  id = null,
  type,
  timestamp = Date.now() / 1000,
  actor = "",
  metadata = {}
} = {}) {
  const normalizedTimestamp = Number(timestamp || Date.now() / 1000);
  return {
    id: safeString(id) || buildTimelineId(normalizedTimestamp),
    type: safeString(type).toLowerCase() || "event",
    timestamp: normalizedTimestamp,
    actor: safeString(actor) || null,
    metadata: metadata && typeof metadata === "object" ? metadata : {}
  };
}

export function normalizeCaseTimelineEvent(entry = {}) {
  if (!entry || typeof entry !== "object") {
    return null;
  }
  const normalized = buildCaseTimelineEvent({
    id: entry.id || entry.eventId,
    type: entry.type || entry.eventType,
    timestamp: entry.timestamp || entry.created_at || entry.createdAt,
    actor: entry.actor || entry.author || entry.username || entry.user,
    metadata: entry.metadata
  });
  return normalized.type ? normalized : null;
}

export function formatCaseTimelineEvent(entry = {}) {
  const metadata = entry?.metadata && typeof entry.metadata === "object" ? entry.metadata : {};
  switch (String(entry?.type || "").toLowerCase()) {
    case "case_created":
      return "Case created";
    case "case_opened":
      return "Case opened";
    case "note_added":
      return "Note added";
    case "enrichment_added":
      return "Enrichment added";
    case "status_changed":
      return `Status changed: ${formatStatusLabel(metadata.from)} -> ${formatStatusLabel(metadata.to)}`;
    case "closure_reason_set":
      return `Closure reason set: ${formatClosureReason(metadata.reason)}`;
    case "case_closed":
      return "Case closed";
    default:
      return safeString(entry?.type).replace(/_/g, " ").replace(/\b\w/g, letter => letter.toUpperCase()) || "Event";
  }
}

export function appendCaseTimelineEvents(existingTimeline = [], nextEvents = []) {
  const current = (Array.isArray(existingTimeline) ? existingTimeline : [])
    .map(normalizeCaseTimelineEvent)
    .filter(Boolean);
  const additions = (Array.isArray(nextEvents) ? nextEvents : [])
    .map(normalizeCaseTimelineEvent)
    .filter(Boolean);
  return [...current, ...additions];
}
