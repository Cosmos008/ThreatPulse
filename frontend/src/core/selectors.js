import { correlateRelatedAlerts } from "./correlation.js";
import { normalizeActionEventModel, normalizeCaseModel } from "./domainModels.js";
import { formatCaseTimelineEvent, normalizeCaseTimelineEvent } from "./caseTimeline.js";

export function selectActiveTriageQueue(appState = {}) {
  return Array.isArray(appState.filteredAlerts) ? appState.filteredAlerts : [];
}

export function selectSelectedAlert(appState = {}) {
  return (Array.isArray(appState.alerts) ? appState.alerts : []).find(alert => String(alert?.id || "") === String(appState.selectedAlertId || "")) || null;
}

export function selectCurrentQueueCase(appState = {}) {
  const cases = Array.isArray(appState.cases) ? appState.cases : [];
  const selectedCaseId = String(appState.selectedCaseId || appState.caseQueue?.activeCaseId || "");
  return cases.find(caseRecord => String(caseRecord?.id || "") === selectedCaseId) || null;
}

export function selectLinkedCaseForAlert(appState = {}, alertId) {
  const normalizedAlertId = String(alertId || "");
  const matchedAlert = (Array.isArray(appState.alerts) ? appState.alerts : []).find(alert => String(alert?.id || "") === normalizedAlertId) || null;
  const explicitCaseId = String(matchedAlert?.mergedIntoCaseId || matchedAlert?.merged_into_case_id || matchedAlert?.caseId || matchedAlert?.case_id || "");
  if (explicitCaseId) {
    return (Array.isArray(appState.cases) ? appState.cases : []).find(caseRecord => String(caseRecord?.id || "") === explicitCaseId) || null;
  }
  return (Array.isArray(appState.cases) ? appState.cases : []).find(caseRecord => {
    const normalizedCase = normalizeCaseModel(caseRecord);
    return normalizedCase.sourceAlertId === normalizedAlertId || normalizedCase.linkedAlertIds.includes(normalizedAlertId);
  }) || null;
}

export function selectRelatedAlerts(appState = {}, alertId) {
  const alerts = Array.isArray(appState.alerts) ? appState.alerts : [];
  const targetAlert = alerts.find(alert => String(alert?.id || "") === String(alertId || ""));
  return targetAlert ? correlateRelatedAlerts(targetAlert, alerts) : [];
}

export function selectCaseTimeline(caseRecord = {}) {
  const timeline = (Array.isArray(caseRecord.timeline) ? caseRecord.timeline : [])
    .map(normalizeCaseTimelineEvent)
    .filter(Boolean)
    .map(entry => ({
      id: entry.id,
      type: entry.type,
      author: entry.actor || "System",
      label: formatCaseTimelineEvent(entry),
      timestamp: entry.timestamp,
      metadata: entry.metadata
    }));
  if (timeline.length) {
    return timeline.sort((left, right) => Number(right.timestamp || 0) - Number(left.timestamp || 0));
  }
  const createdAt = Number(caseRecord.created_at || caseRecord.createdAt || Date.now() / 1000);
  const notes = Array.isArray(caseRecord.notes) ? caseRecord.notes : [];
  const actions = (Array.isArray(caseRecord.actions) ? caseRecord.actions : [])
    .map(normalizeActionEventModel)
    .filter(Boolean)
    .map(action => ({
      type: action.actionType,
      author: action.actor,
      label: action.message || action.actionType,
      timestamp: action.timestamp
    }));
  const noteEntries = notes.map(note => {
    const parsed = normalizeActionEventModel(note);
    if (parsed) {
      return {
        type: parsed.actionType,
        author: parsed.actor,
        label: parsed.message || parsed.actionType,
        timestamp: parsed.timestamp
      };
    }
    return {
      type: "note",
      author: "Unknown",
      label: String(note?.text || note || "").trim(),
      timestamp: Number(note?.timestamp || createdAt)
    };
  });

  return [
    {
      type: "creation",
      author: caseRecord.assignee || caseRecord.created_by || "System",
      label: "Case created",
      timestamp: createdAt
    },
    ...actions,
    ...noteEntries
  ].sort((left, right) => Number(right.timestamp || 0) - Number(left.timestamp || 0));
}

export function selectGlobalActivityStream(appState = {}) {
  const direct = Array.isArray(appState.actionEvents) ? appState.actionEvents : [];
  const caseActions = (Array.isArray(appState.cases) ? appState.cases : [])
    .flatMap(caseRecord => Array.isArray(caseRecord.actions) ? caseRecord.actions : []);
  const merged = [...direct, ...caseActions]
    .map(normalizeActionEventModel)
    .filter(Boolean);
  const seen = new Set();
  return merged.filter(entry => {
    const key = `${entry.actionId}|${entry.timestamp}|${entry.targetId}|${entry.actionType}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  }).sort((left, right) => Number(right.timestamp || 0) - Number(left.timestamp || 0));
}
