import { applyAlertDisposition, applyAlertLifecycle } from "./alertLifecycle.js";
import { getNextQueuedCaseId } from "./caseQueue.js";
import { normalizeCaseQueueModel } from "./domainModels.js";

function cloneCaseQueue(appState = {}) {
  const source = normalizeCaseQueueModel({
    queue: appState.selectedCaseQueue || appState.caseQueue?.queue || [],
    activeCaseId: appState.selectedCaseId || appState.caseQueue?.activeCaseId || null
  });
  return {
    queue: [...source.queue],
    activeCaseId: source.activeCaseId
  };
}

function getNextActiveAlertId(alerts = [], currentAlertId = null) {
  const currentIndex = alerts.findIndex(alert => String(alert?.id || "") === String(currentAlertId || ""));
  if (currentIndex >= 0 && alerts[currentIndex + 1]) {
    return String(alerts[currentIndex + 1].id || "");
  }
  return alerts[0]?.id ? String(alerts[0].id) : null;
}

export function createWorkflowCommands() {
  return {
    selectAlert(appState, alertId) {
      return {
        ...appState,
        selectedAlertId: alertId ? String(alertId) : null
      };
    },

    createCaseFromAlert(appState, alertId, { caseId = null, investigationId = null } = {}) {
      const normalizedAlertId = String(alertId || "");
      const nextAlerts = (Array.isArray(appState.alerts) ? appState.alerts : []).map(alert =>
        String(alert?.id || "") === normalizedAlertId
          ? applyAlertLifecycle({
            ...alert,
            case_id: caseId || alert.case_id || alert.caseId || null,
            caseId: caseId || alert.caseId || alert.case_id || null,
            investigation_id: investigationId || alert.investigation_id || alert.investigationId || null,
            investigationId: investigationId || alert.investigationId || alert.investigation_id || null,
            hasCase: true
          }, "in_case")
          : alert
      );
      const nextFilteredAlerts = (Array.isArray(appState.filteredAlerts) ? appState.filteredAlerts : []).filter(alert => String(alert?.id || "") !== normalizedAlertId);
      return {
        ...appState,
        alerts: nextAlerts,
        filteredAlerts: nextFilteredAlerts,
        selectedAlertId: getNextActiveAlertId(nextFilteredAlerts, normalizedAlertId)
      };
    },

    markAlertFalsePositive(appState, alertId) {
      const normalizedAlertId = String(alertId || "");
      const nextAlerts = (Array.isArray(appState.alerts) ? appState.alerts : []).map(alert =>
        String(alert?.id || "") === normalizedAlertId
          ? applyAlertLifecycle(alert, "false_positive")
          : alert
      );
      const nextFilteredAlerts = (Array.isArray(appState.filteredAlerts) ? appState.filteredAlerts : []).filter(alert => String(alert?.id || "") !== normalizedAlertId);
      return {
        ...appState,
        alerts: nextAlerts,
        filteredAlerts: nextFilteredAlerts,
        selectedAlertId: getNextActiveAlertId(nextFilteredAlerts, normalizedAlertId)
      };
    },

    acknowledgeAlert(appState, alertId, extra = {}) {
      const normalizedAlertId = String(alertId || "");
      const nextAlerts = (Array.isArray(appState.alerts) ? appState.alerts : []).map(alert =>
        String(alert?.id || "") === normalizedAlertId ? applyAlertDisposition(alert, "acknowledged", extra) : alert
      );
      return {
        ...appState,
        alerts: nextAlerts,
        filteredAlerts: (Array.isArray(appState.filteredAlerts) ? appState.filteredAlerts : []).map(alert =>
          String(alert?.id || "") === normalizedAlertId ? applyAlertDisposition(alert, "acknowledged", extra) : alert
        )
      };
    },

    suppressAlert(appState, alertId, extra = {}) {
      const normalizedAlertId = String(alertId || "");
      const nextAlerts = (Array.isArray(appState.alerts) ? appState.alerts : []).map(alert =>
        String(alert?.id || "") === normalizedAlertId ? applyAlertDisposition(alert, "suppressed", extra) : alert
      );
      const nextFilteredAlerts = (Array.isArray(appState.filteredAlerts) ? appState.filteredAlerts : []).filter(alert =>
        String(alert?.id || "") !== normalizedAlertId
      );
      return {
        ...appState,
        alerts: nextAlerts,
        filteredAlerts: nextFilteredAlerts,
        selectedAlertId: getNextActiveAlertId(nextFilteredAlerts, normalizedAlertId)
      };
    },

    reopenAlert(appState, alertId, extra = {}) {
      const normalizedAlertId = String(alertId || "");
      const nextAlerts = (Array.isArray(appState.alerts) ? appState.alerts : []).map(alert =>
        String(alert?.id || "") === normalizedAlertId ? applyAlertDisposition(alert, "reopened", extra) : alert
      );
      return {
        ...appState,
        alerts: nextAlerts,
        filteredAlerts: (Array.isArray(appState.filteredAlerts) ? appState.filteredAlerts : []).map(alert =>
          String(alert?.id || "") === normalizedAlertId ? applyAlertDisposition(alert, "reopened", extra) : alert
        )
      };
    },

    assignAlert(appState, alertId, assignedTo, extra = {}) {
      const normalizedAlertId = String(alertId || "");
      const patch = alert => ({
        ...alert,
        ...extra,
        assigned_to: assignedTo,
        assignedTo,
        analyst: assignedTo
      });
      return {
        ...appState,
        alerts: (Array.isArray(appState.alerts) ? appState.alerts : []).map(alert =>
          String(alert?.id || "") === normalizedAlertId ? patch(alert) : alert
        ),
        filteredAlerts: (Array.isArray(appState.filteredAlerts) ? appState.filteredAlerts : []).map(alert =>
          String(alert?.id || "") === normalizedAlertId ? patch(alert) : alert
        )
      };
    },

    mergeAlertIntoCase(appState, alertId, caseId, extra = {}) {
      const normalizedAlertId = String(alertId || "");
      const nextAlerts = (Array.isArray(appState.alerts) ? appState.alerts : []).map(alert =>
        String(alert?.id || "") === normalizedAlertId
          ? applyAlertLifecycle({
            ...alert,
            ...extra,
            merged_into_case_id: caseId,
            mergedIntoCaseId: caseId,
            case_id: caseId,
            caseId: caseId,
            hasCase: true
          }, "in_case")
          : alert
      );
      const nextFilteredAlerts = (Array.isArray(appState.filteredAlerts) ? appState.filteredAlerts : []).filter(alert =>
        String(alert?.id || "") !== normalizedAlertId
      );
      return {
        ...appState,
        alerts: nextAlerts,
        filteredAlerts: nextFilteredAlerts,
        selectedAlertId: getNextActiveAlertId(nextFilteredAlerts, normalizedAlertId)
      };
    },

    advanceCaseQueue(appState, currentCaseId = null) {
      const caseQueue = cloneCaseQueue(appState);
      const nextCaseId = getNextQueuedCaseId(caseQueue.queue, currentCaseId || caseQueue.activeCaseId);
      return {
        ...appState,
        selectedCaseQueue: [...caseQueue.queue],
        selectedCaseId: nextCaseId ? String(nextCaseId) : null,
        caseQueue: {
          queue: [...caseQueue.queue],
          activeCaseId: nextCaseId ? String(nextCaseId) : null
        }
      };
    },

    closeCase(appState, caseId) {
      const normalizedCaseId = String(caseId || "");
      const caseQueue = cloneCaseQueue(appState);
      caseQueue.queue = caseQueue.queue.filter(entry => entry !== normalizedCaseId);
      const nextCaseId = getNextQueuedCaseId(caseQueue.queue, normalizedCaseId);
      return {
        ...appState,
        selectedCaseQueue: [...caseQueue.queue],
        selectedCaseId: nextCaseId ? String(nextCaseId) : null,
        caseQueue: {
          queue: [...caseQueue.queue],
          activeCaseId: nextCaseId ? String(nextCaseId) : null
        }
      };
    },

    blockIpFromCase(appState, ip) {
      if (!ip) {
        return appState;
      }
      const markBlocked = alert => {
        const sourceIp = String(alert?.sourceIp || alert?.source_ip || alert?.ip || "");
        return sourceIp === String(ip) ? { ...alert, is_blocked: true, isBlocked: true } : alert;
      };
      return {
        ...appState,
        alerts: (Array.isArray(appState.alerts) ? appState.alerts : []).map(markBlocked),
        filteredAlerts: (Array.isArray(appState.filteredAlerts) ? appState.filteredAlerts : []).map(markBlocked)
      };
    }
  };
}
