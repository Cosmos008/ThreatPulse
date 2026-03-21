function safeString(value) {
  return String(value ?? "").trim();
}

export function buildActionObject({
  actionType,
  actor,
  targetType,
  targetId,
  relatedCaseId = null,
  relatedAlertId = null,
  input = null,
  result = null,
  status = "success",
  message = "",
  timestamp = Date.now() / 1000
}) {
  const normalizedActionType = safeString(actionType).toLowerCase().replace(/\s+/g, "_");
  return {
    actionId: `act-${Math.random().toString(16).slice(2, 10)}-${Math.floor(timestamp)}`,
    actionType: normalizedActionType,
    actor: safeString(actor) || "Unknown",
    timestamp,
    targetType: safeString(targetType).toLowerCase() || "system",
    targetId: safeString(targetId) || "-",
    relatedCaseId: relatedCaseId ? safeString(relatedCaseId) : null,
    relatedAlertId: relatedAlertId ? safeString(relatedAlertId) : null,
    input,
    result,
    status: safeString(status).toLowerCase() || "success",
    message: safeString(message)
  };
}

export function encodeActionNote(action) {
  return `[action]${JSON.stringify(action)}`;
}

export function parseActionEntry(entry = {}) {
  if (entry.actionId || entry.actionType) {
    return {
      actionId: safeString(entry.actionId),
      actionType: safeString(entry.actionType).toLowerCase(),
      actor: safeString(entry.actor || entry.username || entry.user),
      timestamp: Number(entry.timestamp || entry.created_at || Date.now() / 1000),
      targetType: safeString(entry.targetType || entry.target_type || "system").toLowerCase(),
      targetId: safeString(entry.targetId || entry.target_id || entry.target || entry.id || "-"),
      relatedCaseId: safeString(entry.relatedCaseId || entry.related_case_id) || null,
      relatedAlertId: safeString(entry.relatedAlertId || entry.related_alert_id || entry.alert_id) || null,
      input: entry.input ?? null,
      result: entry.result ?? null,
      status: safeString(entry.status || "success").toLowerCase(),
      message: safeString(entry.message || entry.details || entry.note)
    };
  }

  const text = safeString(entry.text);
  if (text.startsWith("[action]")) {
    try {
      const parsed = JSON.parse(text.slice(8));
      return parseActionEntry({
        ...parsed,
        timestamp: parsed.timestamp || entry.timestamp
      });
    } catch {
      return null;
    }
  }

  return null;
}

export function formatActionLabel(action) {
  const normalized = safeString(action?.actionType).replace(/_/g, " ").trim();
  return normalized || "activity";
}

export function toActivityEntry(action) {
  const normalized = parseActionEntry(action);
  if (!normalized) {
    return null;
  }
  return {
    timestamp: normalized.timestamp,
    username: normalized.actor,
    action: formatActionLabel(normalized),
    targetType: normalized.targetType,
    target: normalized.targetId,
    details: normalized.message || normalized.status,
    actionObject: normalized
  };
}
