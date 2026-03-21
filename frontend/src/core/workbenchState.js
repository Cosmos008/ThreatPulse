export const workbenchState = {
  currentView: "dashboard",
  selectedAlertId: null,
  selectedEntityKey: "",
  selectedCaseId: null,
};

export function setCurrentView(view) {
  workbenchState.currentView = String(view || "dashboard");
}

export function setSelectedAlertId(alertId) {
  workbenchState.selectedAlertId = alertId ? String(alertId) : null;
}

export function setSelectedEntityKey(entityKey) {
  workbenchState.selectedEntityKey = String(entityKey || "");
}

export function setSelectedCaseId(caseId) {
  workbenchState.selectedCaseId = caseId ? String(caseId) : null;
}
