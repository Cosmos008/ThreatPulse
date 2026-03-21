export const state = {
  alerts: [],
  filteredAlerts: [],
  cases: [],
  investigations: [],
  actionEvents: [],
  watchlist: [],
  onlineUsers: [],
  selectedAlertId: null,
  selectedEntity: "",
  currentInvestigation: null,
  selectedCaseId: null,
  selectedCaseQueue: [],
  currentCasePointer: null,
  caseQueue: {
    queue: [],
    activeCaseId: null
  },
  currentView: "dashboard",
  user: null,
  apiKey: null,
  mode: "demo" // default ALWAYS demo
};
