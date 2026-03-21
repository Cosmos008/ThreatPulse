import { fetchAlertSnapshot } from "./snapshotClient.js";
import { createLiveStream } from "./liveStream.js";
import { createStatsPanel } from "./statsPanel.js";
import { demoAlerts } from "./demoData.js";
import { state } from "./core/state.js";
import { loginSuccess, loadSession, logout as authLogout } from "./core/auth.js";
import { apiFetch } from "./core/api.js";
import { getAlertPrimaryIp, normalizeAlertEnrichment } from "./core/alertEnrichment.js";
import {
  applyAlertLifecycle,
  getAlertLifecycleLabel,
  isAlertEligibleForTriage,
  normalizeAlertLifecycle
} from "./core/alertLifecycle.js";
import { buildActionObject, encodeActionNote, formatActionLabel, parseActionEntry, toActivityEntry } from "./core/actionSystem.js";
import { appendCaseTimelineEvents, buildCaseTimelineEvent } from "./core/caseTimeline.js";
import { getNextQueuedCaseId, getQueuePosition, getQueueVisibleCaseId, syncCaseQueue, toggleCaseQueue } from "./core/caseQueue.js";
import { buildCorrelationKeys, correlateRelatedAlerts } from "./core/correlation.js";
import { normalizeAlertModel, normalizeCaseModel, normalizeEnrichmentRecord } from "./core/domainModels.js";
import { buildEntityProfile, extractAlertEntities } from "./core/entityProfiles.js";
import { selectActiveTriageQueue, selectCurrentQueueCase, selectGlobalActivityStream, selectLinkedCaseForAlert, selectRelatedAlerts, selectSelectedAlert, selectCaseTimeline } from "./core/selectors.js";
import { getIpReputation } from "./core/reputationService.js";
import { createWorkflowCommands } from "./core/workflowCommands.js";
import { workbenchState, setCurrentView, setSelectedAlertId, setSelectedCaseId, setSelectedEntityKey } from "./core/workbenchState.js";
import {
  buildIocPivotTriggerMarkup,
  buildLocalIocPivotPayload,
  escapeHtml as escapeIocHtml,
  getIocLabel,
  normalizeIocType,
  normalizeIocValue
} from "./core/iocPivot.js";
import { buildPivotHuntQuery, filterAlertsByHuntQuery, parseHuntQuery } from "./core/huntQuery.js";
import { showToast, highlight, showLoading, escapeHtml, buildLocalAlertId } from "./ui/components.js";
import { scenarios } from "./scenarios.js";

let isDemoMode = false;
let currentUser = null;
let isEditingApiKey = false;
let loginErrorMessage = "";
const DEMO_CASES_STORAGE_KEY = "cybermap.demoCases";

let refreshInterval = null;
const SESSION_DURATION = 30 * 60 * 1000;
let demoAuditLogs = [];
let activityLogEntries = [];
let currentDemoAlerts = [];
let demoReferenceTime = null;
let isUserInteracting = false;
let selectedAnalystByAlert = {};
let presenceHeartbeatInterval = null;
let adminPresencePollInterval = null;
let adminPresenceUsers = [];
let activeInvestigations = new Map();
let rulesConfig = {};
const allowActionsInDemo = true;
let investigationShortcutInFlight = false;
let investigationShortcutCooldownUntil = 0;
const workflowCommands = createWorkflowCommands();
const pendingAlertWorkflowActions = new Set();
const pendingCaseWorkflowActions = new Set();
let casePlaybookUiState = {};
let availableCaseAssignees = [];
let pendingCaseAssigneeId = null;
let pendingCaseAssigneeSelections = {};
let openExportMenuCaseId = null;
let huntResults = [];
let currentHuntQuery = "";
let currentHuntTimeRange = "24h";
let currentHuntSort = "time_desc";
let currentHuntPayload = null;
let currentHuntCaseStatusFilter = "all";
let currentHuntAttackFilter = "";
let currentHuntAlertStatusFilter = "all";
let currentHuntUserFilter = "";
let currentHuntMinRiskFilter = "";
let playbookDefinitions = [];
let playbookExecutions = [];
let autoExecutedDemoPlaybooks = new Set();
let detectionRules = [];
let selectedDetectionRuleKey = "";
let iocPivotState = {
  open: false,
  loading: false,
  payload: null,
  error: "",
  source: "",
  requestId: 0
};

window.__dashboardUiState = {
  get isUserInteracting() {
    return isUserInteracting;
  },
  get selectedAnalystByAlert() {
    return selectedAnalystByAlert;
  }
};
window.__dashboardIsAdmin = () => state.user?.role === "admin";
window.__dashboardGetCurrentUser = () => state.user ? { ...state.user } : null;
window.__dashboardGetCases = () => Array.isArray(state.cases) ? [...state.cases] : [];
window.__dashboardGetActivityEntries = () => selectGlobalActivityStream(state);
window.__dashboardGetWatchlist = () => Array.isArray(state.watchlist) ? [...state.watchlist] : [];
window.__dashboardGetPlaybooks = () => Array.isArray(playbookDefinitions) ? [...playbookDefinitions] : [];
window.__dashboardGetPlaybookExecutions = () => Array.isArray(playbookExecutions) ? [...playbookExecutions] : [];

function getConfig() {
  const config = window.CYBERMAP_CONFIG || {};
  return {
    apiBaseUrl: localStorage.getItem("cybermap.apiBaseUrl") || config.apiBaseUrl || "http://localhost:8001",
    apiKey: state.apiKey || localStorage.getItem("cybermap.apiKey") || config.apiKey || ""
  };
}

function getDefaultApiBaseUrl() {
  const protocol = window.location.protocol === "https:" ? "https:" : "http:";
  return `${protocol}//${window.location.hostname}:8001`;
}

function getCaseIdFromUrl(urlValue = window.location.href) {
  try {
    const url = new URL(urlValue, window.location.origin);
    const caseId = url.searchParams.get("caseId");
    return caseId ? String(caseId).trim() : "";
  } catch {
    return "";
  }
}

function buildCaseDeepLinkUrl(caseId) {
  const url = new URL(window.location.href);
  if (caseId) {
    url.searchParams.set("caseId", String(caseId));
  } else {
    url.searchParams.delete("caseId");
  }
  return url.toString();
}

async function copyTextToClipboard(value, successMessage, failureMessage) {
  try {
    if (!navigator?.clipboard?.writeText) {
      throw new Error("Clipboard unavailable");
    }
    await navigator.clipboard.writeText(String(value || ""));
    showToast(successMessage);
    return true;
  } catch (error) {
    console.error(error);
    showToast(failureMessage);
    return false;
  }
}

function getStoredAssignableUsers() {
  try {
    const parsed = JSON.parse(localStorage.getItem("cybermap.assignableUsers") || "[]");
    return [...new Set(
      (Array.isArray(parsed) ? parsed : [])
        .map(value => String(value || "").trim())
        .filter(Boolean)
    )].sort((left, right) => String(left).localeCompare(String(right)));
  } catch {
    localStorage.removeItem("cybermap.assignableUsers");
    return [];
  }
}

function loadStoredDemoCases() {
  try {
    const parsed = JSON.parse(localStorage.getItem(DEMO_CASES_STORAGE_KEY) || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    localStorage.removeItem(DEMO_CASES_STORAGE_KEY);
    return [];
  }
}

function persistDemoCases(cases) {
  if (Array.isArray(cases) && cases.length) {
    localStorage.setItem(DEMO_CASES_STORAGE_KEY, JSON.stringify(cases));
  } else {
    localStorage.removeItem(DEMO_CASES_STORAGE_KEY);
  }
}

function requireAuth() {
  if (!state.user?.username) {
    showToast("Please login first");
    throw new Error("Not authenticated");
  }
  if (state.user && Date.now() > Number(state.user.expiresAt || 0)) {
    window.logout?.(true);
    throw new Error("Session expired");
  }
}

function isAdmin() {
  return state.user?.role === "admin";
}

function requireAdmin() {
  if (!isAdmin()) {
    window.alert("Admin only action");
    throw new Error("Admin only");
  }
}

function setInputValue(node, value) {
  if (node) {
    node.value = value;
  }
}


function getInitials(username) {
  if (!username) {
    return "?";
  }

  return username
    .split(/\s+/)
    .filter(Boolean)
    .map(word => word[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();
}


function slugify(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "report";
}

function downloadReportFile(report) {
  const content = JSON.stringify(report, null, 2);
  const blob = new Blob([content], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  const stamp = new Date(report.generatedAt).toISOString().replaceAll(":", "-");

  link.href = url;
  link.download = `${slugify(report.classification)}-${stamp}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function blockIpAddress(apiBaseUrl, apiKey, ip) {
  const response = await fetch(`${apiBaseUrl.replace(/\/+$/, "")}/actions/block-ip`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": apiKey,
      "X-User": currentUser?.username
    },
    body: JSON.stringify({ ip })
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload?.status !== "success") {
    throw new Error(payload?.message || payload?.detail || "Failed to block IP");
  }

  return payload;
}

function buildCaseActivityNote(type, text) {
  const author = state.user?.username || currentUser?.username || "Analyst";
  return { text: `[${type}|${author}] ${text}`, timestamp: Date.now() / 1000 };
}

function getCaseSourceAlert(caseRecord) {
  return caseRecord?.alert || getCaseLinkedAlerts(caseRecord)[0] || null;
}

function getCaseBlockableIp(caseRecord) {
  return getAlertPrimaryIp(getCaseSourceAlert(caseRecord));
}

function markIpBlockedLocally(ip) {
  if (!ip) {
    return;
  }
  state.alerts = (Array.isArray(state.alerts) ? state.alerts : []).map(alert =>
    getAlertPrimaryIp(alert) === ip ? { ...alert, is_blocked: true, isBlocked: true } : alert
  );
  state.filteredAlerts = (Array.isArray(state.filteredAlerts) ? state.filteredAlerts : []).map(alert =>
    getAlertPrimaryIp(alert) === ip ? { ...alert, is_blocked: true, isBlocked: true } : alert
  );
}

function unmarkIpBlockedLocally(ip) {
  if (!ip) {
    return;
  }
  state.alerts = (Array.isArray(state.alerts) ? state.alerts : []).map(alert =>
    getAlertPrimaryIp(alert) === ip ? { ...alert, is_blocked: false, isBlocked: false } : alert
  );
  state.filteredAlerts = (Array.isArray(state.filteredAlerts) ? state.filteredAlerts : []).map(alert =>
    getAlertPrimaryIp(alert) === ip ? { ...alert, is_blocked: false, isBlocked: false } : alert
  );
}

function getBlockedIps() {
  return [...new Set(
    (Array.isArray(state.alerts) ? state.alerts : [])
      .filter(alert => alert?.is_blocked || alert?.isBlocked)
      .map(alert => getAlertPrimaryIp(alert))
      .filter(Boolean)
  )];
}

  function isIpCurrentlyBlocked(ip) {
    const normalizedIp = String(ip || "").trim();
    if (!normalizedIp) {
      return false;
    }
    return getBlockedIps().includes(normalizedIp);
  }

  function isAlertEscalatedToCase(alert) {
    const normalizedStatus = String(alert?.status || "").toLowerCase();
    return Boolean(
      alert?.case_id ||
      alert?.caseId ||
      alert?.mergedIntoCaseId ||
      alert?.merged_into_case_id ||
      alert?.hasCase ||
      normalizedStatus === "in_case" ||
      normalizedStatus === "escalated" ||
      normalizedStatus === "converted_to_case" ||
      normalizedStatus === "processed"
    );
  }

async function postAlertAction(apiBaseUrl, apiKey, path, body) {
  const response = await fetch(`${apiBaseUrl.replace(/\/+$/, "")}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": apiKey,
      "X-User": currentUser?.username
    },
    body: JSON.stringify(body)
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload?.status !== "success") {
    throw new Error(payload?.message || payload?.detail || "Action failed");
  }

  return payload;
}

function updateUI() {
  const apiSection = document.getElementById("api-section");
  const sessionControls = document.getElementById("session-controls");
  const simPanel = document.getElementById("sim-panel");
  const activeView = state.currentView || workbenchState.currentView || "dashboard";
  const showDashboardShellControls = activeView === "dashboard";
  const showAdminApiSettings = showDashboardShellControls && Boolean(state.user?.username) && isAdmin();
  const showSharedDashboardControls = showDashboardShellControls && Boolean(state.user?.username);
  if (apiSection) {
    apiSection.style.display = showAdminApiSettings ? "flex" : "none";
  }
  if (sessionControls) {
    sessionControls.style.display = showSharedDashboardControls ? "flex" : "none";
  }
  if (simPanel) {
    simPanel.style.display = showDashboardShellControls && isDemoMode ? "flex" : "none";
  }
}

async function bootstrap() {
  console.log("BOOTSTRAP SAFE START");
  state.mode = "demo";

  loadSession();
  if (state.user && Date.now() > Number(state.user.expiresAt || 0)) {
    authLogout();
  }
  currentUser = state.user;

  let config = getConfig();
  const endpointNode = document.getElementById("stream-endpoint");
  const apiBaseUrlInput = document.getElementById("api-base-url-input");
  const apiKeyInput = document.getElementById("api-key-input");
  const editApiKeyButton = document.getElementById("edit-api-key");
  const saveKeyButton = document.getElementById("save-api-key");
  const globalSearchNode = document.getElementById("global-search");
  const searchPanelNode = document.getElementById("search-panel");
  const searchStatusNode = document.getElementById("search-status");
  const searchResultsNode = document.getElementById("search-results");
  const huntStatusNode = document.getElementById("hunt-status");
  const huntSummaryNode = document.getElementById("hunt-summary");
  const huntQueryInputNode = document.getElementById("hunt-query-input");
  const huntTimeRangeNode = document.getElementById("hunt-time-range");
  const huntSortNode = document.getElementById("hunt-sort");
  const huntCaseStatusNode = document.getElementById("hunt-case-status");
  const huntAttackFilterNode = document.getElementById("hunt-attack-filter");
  const huntStatusFilterNode = document.getElementById("hunt-status-filter");
  const huntUserFilterNode = document.getElementById("hunt-user-filter");
  const huntMinRiskNode = document.getElementById("hunt-min-risk");
  const huntResultsBodyNode = document.getElementById("hunt-results-body");
  const huntRunButton = document.getElementById("hunt-run");
  const showDemoButton = document.getElementById("show-demo");
  const reloadButton = document.getElementById("reload-dashboard");
  const refreshNowButton = document.getElementById("refresh-now");
  const downloadReportButton = document.getElementById("download-report");
  const loginButton = document.getElementById("login-button");
  const authGateNode = document.getElementById("auth-gate");
  const usernameNode = document.getElementById("username");
  const passwordNode = document.getElementById("password");
  const passwordToggleNode = document.getElementById("password-toggle");
  const loginErrorNode = document.getElementById("login-error");
  const currentUserNode = document.getElementById("current-user");
  const userContainerNode = document.getElementById("user-container");
  const userAvatarNode = document.getElementById("user-avatar");
  const userNameNode = document.getElementById("user-name");
  const userRoleNode = document.getElementById("user-role");
  const logoutButton = document.getElementById("logout-btn");
  const reportClassificationNode = document.getElementById("report-classification");
  const reportNotesNode = document.getElementById("report-notes");
  const reportStatusNode = document.getElementById("report-status");
  const casesStatusNode = document.getElementById("cases-status");
  const casesListNode = document.getElementById("cases-list");
  const caseDetailNode = document.getElementById("case-detail");
  const caseFilterStatusNode = document.getElementById("case-filter-status");
  const caseFilterPriorityNode = document.getElementById("case-filter-priority");
  const caseSortNode = document.getElementById("case-sort");
  const caseTabActiveNode = document.getElementById("case-tab-active");
  const caseTabClosedNode = document.getElementById("case-tab-closed");
  const activityStatusNode = document.getElementById("activity-status");
  const activityOnlineCountNode = document.getElementById("activity-online-count");
  const activityOnlineStatusNode = document.getElementById("activity-online-status");
  const activityOnlineUsersNode = document.getElementById("activity-online-users");
  const activityListNode = document.getElementById("activity-list");
  const activityFilterUserNode = document.getElementById("activity-filter-user");
  const activityFilterActionNode = document.getElementById("activity-filter-action");
  const activityFilterTargetNode = document.getElementById("activity-filter-target");
  const apiHintNode = document.getElementById("api-hint");
  const refreshStatusNode = document.getElementById("refresh-status");
  const refreshMessageNode = document.getElementById("refresh-message");
  const refreshCountdownNode = document.getElementById("refresh-countdown");
  const refreshIndicatorNode = document.getElementById("refresh-indicator");
  const liveStatusNode = document.getElementById("live-status");
  const lastUpdatedNode = document.getElementById("last-updated");
  const adminPanelNode = document.getElementById("admin-panel");
  const presencePanelNode = document.getElementById("presence-panel");
  const typingPanelNode = document.getElementById("typing-panel");
  const slaPanelNode = document.getElementById("sla-panel");
  const rulesPanelNode = document.getElementById("rules-panel");
  const playbooksPanelNode = document.getElementById("playbooks-panel");
  const detectionRulesStatusNode = document.getElementById("detection-rules-status");
  const detectionRulesListNode = document.getElementById("detection-rules-list");
  const detectionRuleEditorNode = document.getElementById("detection-rule-editor");
  const detectionRuleEditorStatusNode = document.getElementById("detection-rule-editor-status");

  const sidebarNode = document.getElementById("sidebar");
  const appHeaderNode = document.getElementById("app-header");
  const connectionNode = document.getElementById("connection-status");
  const totalAttacksNode = document.getElementById("total-attacks");
  const attacksPerMinuteNode = document.getElementById("attacks-per-minute");
  const uniqueIpsNode = document.getElementById("unique-ips");
  const highSeverityPercentNode = document.getElementById("high-severity-percent");
  const honeypotTriggersNode = document.getElementById("honeypot-triggers");
  const honeypotLastTriggeredNode = document.getElementById("honeypot-last-triggered");
  const topCorrelatedIpNode = document.getElementById("top-correlated-ip");
  const severityBreakdownNode = document.getElementById("severity-breakdown");
  const countryTotalNode = document.getElementById("country-total");
  const topCountriesNode = document.getElementById("top-countries");
  const topAttackTypesNode = document.getElementById("top-attack-types");
  const recentCriticalAlertsNode = document.getElementById("recent-critical-alerts");
  const watchlistStatusNode = document.getElementById("watchlist-status");
  const watchlistPanelNode = document.getElementById("watchlist-panel");
  const timelineCanvas = document.getElementById("timeline-canvas");
  const heatmapNode = document.getElementById("heatmap");
  const socEventFeedNode = document.getElementById("soc-event-feed");
  const socFeedCountNode = document.getElementById("soc-feed-count");
  const filterSeverityNode = document.getElementById("filter-severity");
  const filterIpNode = document.getElementById("filter-ip");
  const filterCountryNode = document.getElementById("filter-country");
  const filterStatusNode = document.getElementById("filter-status");
  const filterAttackTypeNode = document.getElementById("filter-attack-type");
  const filterTimeRangeNode = document.getElementById("filter-time-range");
  const filterSortNode = document.getElementById("filter-sort");
  const detailStatusNode = document.getElementById("detail-status");
  const alertDetailNode = document.getElementById("alert-detail");
  const correlationViewNode = document.getElementById("correlation-view");
  const auditPanelNode = document.getElementById("audit-panel");
  const analystListNode = document.getElementById("analyst-list");

  const statsPanel = createStatsPanel({
    connectionNode,
    totalAttacksNode,
    attacksPerMinuteNode,
    uniqueIpsNode,
    highSeverityPercentNode,
    honeypotTriggersNode,
    honeypotLastTriggeredNode,
    topCorrelatedIpNode,
    severityBreakdownNode,
    countryTotalNode,
    topCountriesNode,
    topAttackTypesNode,
    recentCriticalAlertsNode,
    watchlistStatusNode,
    watchlistPanelNode,
    timelineCanvas,
    heatmapNode,
    eventFeedNode: [socEventFeedNode].filter(Boolean),
    feedCountNode: [socFeedCountNode].filter(Boolean),
    filterSeverityNode,
    filterIpNode,
    filterCountryNode,
    filterStatusNode,
    filterAttackTypeNode,
    filterTimeRangeNode,
    filterSortNode,
    detailStatusNode,
    alertDetailNode,
    correlationViewNode,
    auditPanelNode,
    analystListNode
  });

  function findAlertByAnyId(alertRef) {
    if (!alertRef) {
      return null;
    }

    if (typeof alertRef === "object") {
      const candidateIds = [
        alertRef.source_alert_id,
        alertRef.sourceAlertId,
        alertRef.alert_id,
        alertRef.alert?.id,
        ...(Array.isArray(alertRef.linked_alert_ids) ? alertRef.linked_alert_ids : []),
        alertRef.raw?.id,
        alertRef.id
      ]
        .map(value => String(value || "").trim())
        .filter(Boolean);
      for (const candidateId of candidateIds) {
        const resolvedAlert = findAlertByAnyId(candidateId);
        if (resolvedAlert) {
          return resolvedAlert;
        }
      }
      return alertRef;
    }

    const normalized = String(alertRef);
    return statsPanel.getAlertById?.(normalized)
      || (statsPanel.getAlerts?.() || []).find(alert =>
        String(alert.raw?.id || alert.id || "") === normalized
      )
      || null;
  }

  function getFrontendAlertId(alertRef) {
    const alert = findAlertByAnyId(alertRef);
    return alert ? String(alert.id || "") : String(alertRef || "");
  }

  function getBackendAlertId(alertRef) {
    const alert = findAlertByAnyId(alertRef);
    if (alert) {
      return String(alert.raw?.id || alert.id || "");
    }
    return String(alertRef || "");
  }

  function createIocPivotDrawer() {
    let node = document.getElementById("ioc-pivot-drawer");
    if (node) {
      return node;
    }
    node = document.createElement("aside");
    node.id = "ioc-pivot-drawer";
    node.className = "ioc-pivot-drawer";
    node.setAttribute("aria-live", "polite");
    node.setAttribute("aria-hidden", "true");
    document.body.appendChild(node);
    return node;
  }

  const iocPivotDrawerNode = createIocPivotDrawer();

  function getLocalIocPivotPayload(iocType, value) {
    return buildLocalIocPivotPayload({
      iocType,
      value,
      alerts: state.alerts,
      cases: state.cases,
      activityEntries: selectGlobalActivityStream(state),
      watchlist: state.watchlist
    });
  }

  async function lookupIocPivot(iocType, value) {
    if (state.mode !== "demo" && state.apiKey) {
      try {
        return await requestJson(`/iocs/pivot?type=${encodeURIComponent(iocType)}&value=${encodeURIComponent(value)}`);
      } catch (error) {
        console.error("IOC pivot API failed, falling back to local data:", error);
      }
    }
    return getLocalIocPivotPayload(iocType, value);
  }

  function closeIocPivot() {
    iocPivotState = {
      ...iocPivotState,
      open: false,
      loading: false,
      error: "",
      payload: null,
      source: ""
    };
    renderIocPivotDrawer();
  }

  function buildIocPivotSummaryCard(label, value) {
    return `
      <div class="ioc-pivot-stat">
        <span class="ioc-pivot-stat-label">${escapeIocHtml(label)}</span>
        <strong>${escapeIocHtml(String(value ?? 0))}</strong>
      </div>
    `;
  }

  function renderIocPivotSection(title, itemsMarkup, emptyMessage) {
    return `
      <section class="ioc-pivot-section">
        <div class="ioc-pivot-section-header">
          <h3>${escapeIocHtml(title)}</h3>
        </div>
        ${itemsMarkup || `<div class="detail-empty-inline">${escapeIocHtml(emptyMessage)}</div>`}
      </section>
    `;
  }

  function renderIocPivotDrawer() {
    if (!iocPivotDrawerNode) {
      return;
    }

    if (!iocPivotState.open) {
      iocPivotDrawerNode.classList.remove("is-open");
      iocPivotDrawerNode.setAttribute("aria-hidden", "true");
      iocPivotDrawerNode.innerHTML = "";
      return;
    }

    const payload = iocPivotState.payload;
    const ioc = payload?.ioc || {};
    const summary = payload?.summary || {};
    const watchlistEntry = payload?.watchlist_entry || null;
    const relatedAlerts = Array.isArray(payload?.related_alerts) ? payload.related_alerts : [];
    const relatedCases = Array.isArray(payload?.related_cases) ? payload.related_cases : [];
    const recentActivity = Array.isArray(payload?.recent_activity) ? payload.recent_activity : [];
    const canManageWatchlist = state.mode !== "demo" && Boolean(state.apiKey);

    iocPivotDrawerNode.classList.add("is-open");
    iocPivotDrawerNode.setAttribute("aria-hidden", "false");
    iocPivotDrawerNode.innerHTML = `
      <div class="ioc-pivot-drawer-header">
        <div class="ioc-pivot-heading">
          <span class="ioc-pivot-type">${escapeIocHtml(getIocLabel(ioc.type))}</span>
          <h2>${escapeIocHtml(ioc.value || "")}</h2>
          <div class="ioc-pivot-meta">
            <span class="record-badge">${escapeIocHtml(getIocLabel(ioc.type))}</span>
            ${summary.watchlist_hit ? '<span class="watchlist-badge">Watchlist</span>' : ""}
            <span class="panel-note">${escapeIocHtml(ioc.normalized_value || "")}</span>
          </div>
        </div>
        <button type="button" class="button button-secondary button-compact" data-ioc-pivot-close="true">Close</button>
      </div>
      ${iocPivotState.loading ? `
        <div class="ioc-pivot-loading">
          <div class="panel-note">Loading pivot data...</div>
        </div>
      ` : iocPivotState.error ? `
        <div class="ioc-pivot-loading">
          <div class="login-error" style="display:block;">${escapeIocHtml(iocPivotState.error)}</div>
        </div>
      ` : `
        <div class="ioc-pivot-summary">
          ${buildIocPivotSummaryCard("Related Alerts", summary.related_alerts_count || 0)}
          ${buildIocPivotSummaryCard("Related Cases", summary.related_cases_count || 0)}
          ${buildIocPivotSummaryCard("Recurrence", summary.recurrence_count || 0)}
          ${buildIocPivotSummaryCard("Recent Activity", summary.activity_count || 0)}
        </div>
        ${watchlistEntry ? `
          <div class="ioc-pivot-watchlist">
            <div>
              <strong>Watchlist status</strong>
              <div class="panel-note">Tracked by ${escapeIocHtml(watchlistEntry.created_by || "Unknown")} · ${escapeIocHtml(String(watchlistEntry.hits_count || 0))} alert hits</div>
            </div>
            ${canManageWatchlist ? `
              <button
                type="button"
                class="button button-secondary button-compact"
                data-watchlist-action="remove"
                data-watchlist-type="${escapeIocHtml(ioc.type || "")}"
                data-watchlist-value="${escapeIocHtml(ioc.value || "")}"
              >Remove from watchlist</button>
            ` : '<div class="panel-note">Watchlist updates are hidden in demo mode.</div>'}
          </div>
        ` : `
          <div class="ioc-pivot-watchlist">
            <div>
              <strong>Watchlist status</strong>
              <div class="panel-note">This IOC is not currently tracked.</div>
            </div>
            ${canManageWatchlist ? `
              <button
                type="button"
                class="button button-secondary button-compact"
                data-watchlist-action="add"
                data-watchlist-type="${escapeIocHtml(ioc.type || "")}"
                data-watchlist-value="${escapeIocHtml(ioc.value || "")}"
              >Add to watchlist</button>
            ` : '<div class="panel-note">Watchlist updates are hidden in demo mode.</div>'}
          </div>
        `}
        ${renderIocPivotSection(
          "Related Alerts",
          relatedAlerts.map(alert => `
            <button type="button" class="related-item related-item-open" data-ioc-open-alert="${escapeIocHtml(String(alert.id || ""))}">
              <span>${escapeIocHtml(alert.attack_type || "Alert")}</span>
              <span>${escapeIocHtml(String(alert.severity || "medium").toUpperCase())} · ${escapeIocHtml(String(alert.status || "new"))}</span>
              <span>${escapeIocHtml(formatAbsoluteTime(alert.timestamp || 0))}</span>
              <span>${escapeIocHtml(alert.case_name || alert.case_id || "No linked case")}</span>
            </button>
          `).join(""),
          "No related alerts found"
        )}
        ${renderIocPivotSection(
          "Related Cases",
          relatedCases.map(caseRecord => `
            <button type="button" class="related-item related-item-open" data-ioc-open-case="${escapeIocHtml(String(caseRecord.id || caseRecord.case_id || ""))}">
              <span>${escapeIocHtml(caseRecord.case_name || caseRecord.id || "Case")}</span>
              <span>${escapeIocHtml(String(caseRecord.priority || "medium").toUpperCase())} · ${escapeIocHtml(String(caseRecord.status || "open"))}</span>
              <span>${escapeIocHtml(caseRecord.assignee || "Unassigned")}</span>
              <span>${escapeIocHtml(formatAbsoluteTime(caseRecord.updated_at || 0))}</span>
            </button>
          `).join(""),
          "No related cases found"
        )}
        ${renderIocPivotSection(
          "Recent Activity",
          recentActivity.map(entry => `
            <div class="ioc-pivot-activity-item">
              <div class="ioc-pivot-activity-copy">
                <strong>${escapeIocHtml(entry.action || "Activity")}</strong>
                <span>${escapeIocHtml(entry.message || `${entry.actor || "Unknown"} touched ${entry.object_type || "record"} ${entry.object_id || ""}`)}</span>
              </div>
              <div class="ioc-pivot-activity-meta">
                <span>${escapeIocHtml(entry.actor || "Unknown")}</span>
                <span>${escapeIocHtml(formatAbsoluteTime(entry.timestamp || 0))}</span>
              </div>
            </div>
          `).join(""),
          "No recent activity found"
        )}
      `}
    `;

    iocPivotDrawerNode.querySelector("[data-ioc-pivot-close]")?.addEventListener("click", closeIocPivot);
    iocPivotDrawerNode.querySelectorAll("[data-ioc-open-alert]").forEach(button => {
      button.addEventListener("click", () => {
        window.openInvestigation?.(button.getAttribute("data-ioc-open-alert"), { forceVisible: true });
      });
    });
    iocPivotDrawerNode.querySelectorAll("[data-ioc-open-case]").forEach(button => {
      button.addEventListener("click", () => {
        const caseId = String(button.getAttribute("data-ioc-open-case") || "");
        if (!caseId) {
          return;
        }
        const matchedCase = casesCache.find(entry => String(entry.id) === caseId) || null;
        if (matchedCase) {
          selectedCaseTab = normalizeCaseStatus(matchedCase.status) === "closed" ? "closed" : "active";
        }
        setCurrentCaseSelection(caseId, { preserveWorkspaceTab: true });
        showView("cases");
        renderCasesView();
      });
    });
    iocPivotDrawerNode.querySelectorAll("[data-watchlist-action]").forEach(button => {
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

  async function openIocPivot(iocType, value, source = "detail") {
    const normalizedType = normalizeIocType(iocType);
    const rawValue = String(value || "").trim();
    if (!normalizedType || !rawValue) {
      return;
    }
    const requestId = iocPivotState.requestId + 1;
    iocPivotState = {
      ...iocPivotState,
      open: true,
      loading: true,
      error: "",
      source,
      payload: {
        ioc: {
          type: normalizedType,
          value: rawValue,
          normalized_value: normalizeIocValue(normalizedType, rawValue)
        }
      },
      requestId
    };
    renderIocPivotDrawer();

    try {
      const payload = await lookupIocPivot(normalizedType, rawValue);
      if (iocPivotState.requestId !== requestId) {
        return;
      }
      iocPivotState = {
        ...iocPivotState,
        loading: false,
        payload,
        error: ""
      };
    } catch (error) {
      if (iocPivotState.requestId !== requestId) {
        return;
      }
      iocPivotState = {
        ...iocPivotState,
        loading: false,
        error: error.message || "Failed to load IOC pivot data"
      };
    }
    renderIocPivotDrawer();
  }

  window.openIocPivot = openIocPivot;
  window.closeIocPivot = closeIocPivot;

  if (sidebarNode) {
    sidebarNode.innerHTML = `
      <div class="sidebar-header">
        <span class="logo">🛡️</span>
        <span class="title">ThreatPulse</span>
      </div>

      <nav class="nav">
        <button class="nav-item active" data-view="dashboard">Dashboard</button>
        <button class="nav-item" data-view="hunt">Hunt</button>
        <button class="nav-item" data-view="investigations">Investigations</button>
        <button class="nav-item" data-view="cases">Cases</button>
        <button class="nav-item" data-view="activity">Activity</button>

        <button class="nav-item admin-only" data-view="admin">Admin</button>
        <button class="nav-item admin-only" data-view="detection-rules">Detection Rules</button>
      </nav>
    `;
  }

  const views = {
    dashboard: document.getElementById("view-dashboard"),
    investigations: document.getElementById("view-investigations"),
    hunt: document.getElementById("view-hunt"),
    cases: document.getElementById("view-cases"),
    activity: document.getElementById("view-activity"),
    admin: document.getElementById("view-admin"),
    "detection-rules": document.getElementById("view-detection-rules")
  };

  let currentView = workbenchState.currentView;

  function isAuthenticated() {
    return Boolean(state.user?.username);
  }

  function syncApiKeyField() {
    if (!apiKeyInput || !editApiKeyButton) {
      return;
    }

    const hasSavedKey = Boolean(config.apiKey || state.apiKey);
    apiKeyInput.type = "password";
    apiKeyInput.autocomplete = "off";

    if (!isAuthenticated() || !isAdmin()) {
      isEditingApiKey = false;
      apiKeyInput.value = "";
      apiKeyInput.placeholder = "Required";
      apiKeyInput.disabled = true;
      editApiKeyButton.style.display = "none";
      return;
    }

    editApiKeyButton.style.display = "inline-flex";

    if (hasSavedKey && !isEditingApiKey) {
      apiKeyInput.value = "";
      apiKeyInput.placeholder = "Saved";
      apiKeyInput.disabled = true;
      editApiKeyButton.textContent = "Edit API Key";
      return;
    }

    apiKeyInput.disabled = false;
    apiKeyInput.placeholder = hasSavedKey ? "Enter new API key" : "Required";
    editApiKeyButton.textContent = hasSavedKey ? "Cancel" : "Edit API Key";
  }

  function syncAuthGateUi() {
    const authenticated = isAuthenticated();
    if (authGateNode) {
      authGateNode.classList.toggle("is-active", !authenticated);
      authGateNode.style.display = authenticated ? "none" : "block";
    }
    if (sidebarNode) {
      sidebarNode.style.display = authenticated ? "flex" : "none";
    }
    if (appHeaderNode) {
      appHeaderNode.style.display = authenticated ? "flex" : "none";
    }
    if (!authenticated) {
      if (searchPanelNode) {
        searchPanelNode.style.display = "none";
      }
      [document.querySelector(".status-bar"), document.getElementById("api-section"), document.getElementById("session-controls"), document.getElementById("sim-panel")].forEach(node => {
        if (node) {
          node.style.display = "none";
        }
      });
      Object.values(views).forEach(node => {
        if (node) {
          node.style.display = "none";
          node.classList.remove("active-view");
        }
      });
    }
    syncApiKeyField();
  }

  function setLoginError(message = "") {
    loginErrorMessage = String(message || "").trim();
    if (!loginErrorNode) {
      return;
    }
    loginErrorNode.textContent = loginErrorMessage;
    loginErrorNode.style.display = loginErrorMessage ? "block" : "none";
  }

  function requireAuthenticatedUi() {
    if (isAuthenticated()) {
      return true;
    }
    syncAuthGateUi();
    return false;
  }

  function syncFilteredAlertsState() {
    state.filteredAlerts = Array.isArray(statsPanel.getFilteredAlerts?.()) ? statsPanel.getFilteredAlerts() : [];
  }

  function syncCaseQueueState() {
    state.selectedCaseId = selectedCaseId || null;
    state.selectedCaseQueue = [...selectedCaseQueue];
    state.currentCasePointer = selectedCaseId || null;
    state.caseQueue = {
      queue: [...selectedCaseQueue],
      activeCaseId: selectedCaseId || null
    };
  }

  function setCasesState(nextCases) {
    casesCache = Array.isArray(nextCases) ? nextCases.map(normalizeCaseModel) : [];
    state.cases = [...casesCache];
    if (isDemoMode || state.mode === "demo") {
      persistDemoCases(casesCache);
    }
    syncCaseQueueState();
    if (!suppressCaseAutoNavigation) {
      applyPendingCaseDeepLink({ notifyIfMissing: true });
    }
  }

  function updateCaseLocally(caseId, updater) {
    let updatedCase = null;
    const nextCases = casesCache.map(entry => {
      if (String(entry.id) !== String(caseId)) {
        return entry;
      }
      updatedCase = normalizeCaseModel(updater(entry));
      return updatedCase;
    });
    if (updatedCase) {
      setCasesState(nextCases);
    }
    return updatedCase;
  }

  function setInvestigationsState(nextInvestigations) {
    investigationsCache = Array.isArray(nextInvestigations) ? nextInvestigations : [];
    state.investigations = [...investigationsCache];
  }

  function applyWorkflowState(nextState) {
    if (!nextState || typeof nextState !== "object") {
      return;
    }
    if (Array.isArray(nextState.alerts)) {
      const normalizedAlerts = nextState.alerts.map(normalizeAlertModel);
      statsPanel.setAlerts(normalizedAlerts);
      state.alerts = Array.isArray(statsPanel.getAlerts?.()) ? statsPanel.getAlerts() : normalizedAlerts;
    }
    if (Array.isArray(nextState.filteredAlerts)) {
      state.filteredAlerts = nextState.filteredAlerts.map(normalizeAlertModel);
    } else {
      syncFilteredAlertsState();
    }
    if ("selectedAlertId" in nextState) {
      state.selectedAlertId = nextState.selectedAlertId ? String(nextState.selectedAlertId) : null;
      setSelectedAlertId(state.selectedAlertId);
    }
    if (Array.isArray(nextState.selectedCaseQueue)) {
      selectedCaseQueue = [...nextState.selectedCaseQueue];
    }
    if ("selectedCaseId" in nextState) {
      setCurrentCaseSelection(nextState.selectedCaseId, { preserveWorkspaceTab: true });
    }
    if (nextState.caseQueue) {
      state.caseQueue = {
        queue: Array.isArray(nextState.caseQueue.queue) ? [...nextState.caseQueue.queue] : [],
        activeCaseId: nextState.caseQueue.activeCaseId ? String(nextState.caseQueue.activeCaseId) : null
      };
      state.currentCasePointer = state.caseQueue.activeCaseId;
    } else {
      syncCaseQueueState();
    }
  }

  function makePendingActionKey(scope, id) {
    return `${scope}:${String(id || "")}`;
  }

  function beginPendingAlertAction(actionType, alertId) {
    const key = makePendingActionKey(actionType, alertId);
    if (!alertId || pendingAlertWorkflowActions.has(key)) {
      return null;
    }
    pendingAlertWorkflowActions.add(key);
    return key;
  }

  function endPendingAlertAction(key) {
    if (key) {
      pendingAlertWorkflowActions.delete(key);
    }
  }

  function beginPendingCaseAction(actionType, caseId) {
    const key = makePendingActionKey(actionType, caseId);
    if (!caseId || pendingCaseWorkflowActions.has(key)) {
      return null;
    }
    pendingCaseWorkflowActions.add(key);
    return key;
  }

  function endPendingCaseAction(key) {
    if (key) {
      pendingCaseWorkflowActions.delete(key);
    }
  }

  function getCasePlaybookUiState(caseId) {
    const normalizedCaseId = String(caseId || "").trim();
    if (!normalizedCaseId) {
      return { isRunning: false, lastError: "", lastAction: "" };
    }
    return {
      isRunning: false,
      lastError: "",
      lastAction: "",
      ...(casePlaybookUiState[normalizedCaseId] || {})
    };
  }

  function setCasePlaybookUiState(caseId, patch = {}) {
    const normalizedCaseId = String(caseId || "").trim();
    if (!normalizedCaseId) {
      return;
    }
    const nextState = {
      ...getCasePlaybookUiState(normalizedCaseId),
      ...patch
    };
    if (!nextState.isRunning && !nextState.lastError && !nextState.lastAction) {
      delete casePlaybookUiState[normalizedCaseId];
      return;
    }
    casePlaybookUiState = {
      ...casePlaybookUiState,
      [normalizedCaseId]: nextState
    };
  }

  function clearCasePlaybookUiState(caseId) {
    const normalizedCaseId = String(caseId || "").trim();
    if (!normalizedCaseId || !casePlaybookUiState[normalizedCaseId]) {
      return;
    }
    const nextState = { ...casePlaybookUiState };
    delete nextState[normalizedCaseId];
    casePlaybookUiState = nextState;
  }

  function clearCasePlaybookUiStateForIp(ip) {
    const normalizedIp = String(ip || "").trim();
    if (!normalizedIp) {
      return;
    }
    casesCache.forEach(caseRecord => {
      const caseIp = getCaseBlockableIp(caseRecord);
      const linkedAlertMatches = getCaseLinkedAlerts(caseRecord)
        .some(alert => getAlertPrimaryIp(alert) === normalizedIp);
      if (caseIp === normalizedIp || linkedAlertMatches) {
        clearCasePlaybookUiState(caseRecord.id);
      }
    });
  }

  function getLocalAlertCollection() {
    return Array.isArray(statsPanel.getAlerts?.()) ? statsPanel.getAlerts() : state.alerts;
  }

  function updateAlertLifecycleLocally(alertRef, lifecycle, extra = {}) {
    const frontendAlertId = getFrontendAlertId(alertRef);
    const backendAlertId = getBackendAlertId(alertRef);
    const nextAlerts = getLocalAlertCollection().map(alert => {
      const matches = String(alert.id || "") === frontendAlertId
        || String(alert.raw?.id || alert.alert_id || "") === backendAlertId;
      return normalizeAlertModel(matches ? applyAlertLifecycle(alert, lifecycle, extra) : alert);
    });
    statsPanel.setAlerts(nextAlerts);
    state.alerts = Array.isArray(statsPanel.getAlerts?.()) ? statsPanel.getAlerts() : nextAlerts;
    syncFilteredAlertsState();
    return frontendAlertId;
  }

  function patchAlertLocally(alertRef, updater) {
    const frontendAlertId = getFrontendAlertId(alertRef);
    const backendAlertId = getBackendAlertId(alertRef);
    const currentAlerts = getLocalAlertCollection();
    let previousAlert = null;
    const nextAlerts = currentAlerts.map(alert => {
      const matches = String(alert.id || "") === frontendAlertId
        || String(alert.raw?.id || "") === backendAlertId;
      if (!matches) {
        return alert;
      }
      previousAlert = { ...alert };
      return normalizeAlertModel(updater(alert));
    });
    statsPanel.setAlerts(nextAlerts);
    state.alerts = Array.isArray(statsPanel.getAlerts?.()) ? statsPanel.getAlerts() : nextAlerts;
    syncFilteredAlertsState();
    return { frontendAlertId, previousAlert };
  }

  function restorePatchedAlert(previousAlert) {
    if (!previousAlert?.id) {
      return;
    }
    patchAlertLocally(previousAlert.id, () => previousAlert);
  }

  function dispatchSocAction(actionConfig, { reflectActivity = true } = {}) {
    const action = actionConfig?.actionId ? (parseActionEntry(actionConfig) || actionConfig) : buildActionObject(actionConfig);
    state.actionEvents = [...(Array.isArray(state.actionEvents) ? state.actionEvents : []), action].slice(-500);
    if (reflectActivity) {
      const derivedActivity = selectGlobalActivityStream(state).map(toActivityEntry).filter(Boolean);
      if (derivedActivity.length) {
        activityLogEntries = mergeActivityLogs(activityLogEntries, derivedActivity);
      }
      if (state.currentView === "activity") {
        renderActivityView();
      }
    }
    return action;
  }

  function markAlertCaseCreatedLocally(alertId, { caseId = null, investigationId = null } = {}) {
    const normalizedAlertId = String(alertId || "");
    if (!normalizedAlertId) {
      return false;
    }
    const resolvedAlert = findAlertByAnyId(normalizedAlertId);
    const resolvedFrontendId = String(resolvedAlert?.id || normalizedAlertId);
    const resolvedBackendId = String(resolvedAlert?.raw?.id || resolvedAlert?.alert_id || "");
    const sourceAlerts = Array.isArray(statsPanel.getAlerts?.()) ? statsPanel.getAlerts() : state.alerts;
    let didUpdate = false;
    const nextAlerts = (Array.isArray(sourceAlerts) ? sourceAlerts : []).map(alert => {
      const candidateFrontendId = String(alert?.id || "");
      const candidateBackendId = String(alert?.raw?.id || alert?.alert_id || "");
      const isTargetAlert = candidateFrontendId === resolvedFrontendId
        || candidateFrontendId === normalizedAlertId
        || (resolvedBackendId && candidateBackendId === resolvedBackendId)
        || candidateBackendId === normalizedAlertId;
      if (!isTargetAlert) {
        return alert;
      }
      didUpdate = true;
      return applyAlertLifecycle({
        ...alert,
        case_id: caseId || alert.case_id || alert.caseId || null,
        caseId: caseId || alert.caseId || alert.case_id || null,
        investigation_id: investigationId || alert.investigation_id || alert.investigationId || null,
        investigationId: investigationId || alert.investigationId || alert.investigation_id || null,
        hasCase: true,
      }, "in_case");
    });
    if (!didUpdate) {
      return false;
    }
    statsPanel.setAlerts(nextAlerts);
    state.alerts = Array.isArray(statsPanel.getAlerts?.()) ? statsPanel.getAlerts() : nextAlerts;
    syncFilteredAlertsState();
    applyWorkflowState(workflowCommands.createCaseFromAlert(state, resolvedFrontendId, { caseId, investigationId }));
    return true;
  }

  function buildInvestigationContext(alertRef) {
    const normalizedRef = String(alertRef || "");
    const alert = state.alerts.find(entry =>
      String(entry.id || "") === normalizedRef ||
      String(entry.raw?.id || "") === normalizedRef
    ) || findAlertByAnyId(alertRef);
    if (!alert) {
      return null;
    }

    const entityKey = String(alert.sourceIp || alert.source_ip || "");
    const relatedAlerts = state.alerts.filter(entry => String(entry.sourceIp || entry.source_ip || "") === entityKey);

    return {
      entityKey,
      selectedAlertId: String(alert.id || ""),
      relatedAlertIds: relatedAlerts.map(entry => entry.id),
      relatedAlerts
    };
  }

  function focusInvestigationContext(alertRef) {
    console.log("INVESTIGATE_HANDLER:focusInvestigationContext");
    const context = buildInvestigationContext(alertRef);
    if (!context) {
      return null;
    }

    state.selectedEntity = context.entityKey;
    state.selectedAlertId = context.selectedAlertId;
    state.currentInvestigation = context;
    setSelectedEntityKey(context.entityKey);
    setSelectedAlertId(context.selectedAlertId);
    return context;
  }

  function activateViewFrame(name) {
    console.log("INVESTIGATE_HANDLER:activateViewFrame");
    if (!requireAuthenticatedUi()) {
      return;
    }
    currentView = name;
    state.currentView = name;
    setCurrentView(name);
    Object.entries(views).forEach(([key, v]) => {
      if (v) {
        v.style.display = "none";
        v.classList.toggle("active-view", key === name);
      }
    });

    if (views[name]) {
      views[name].style.display = "block";
    }

    document.querySelectorAll(".nav-item").forEach(btn => {
      btn.classList.toggle("active", btn.dataset.view === name);
    });

    syncSearchVisibility(name);
    syncShellControlsVisibility(name);
  }

  function syncSearchVisibility(viewName = currentView) {
    const showQuickSearch = isAuthenticated();
    if (globalSearchNode) {
      if (globalSearchNode.parentElement) {
        globalSearchNode.parentElement.style.display = showQuickSearch ? "flex" : "none";
      }
      globalSearchNode.style.display = showQuickSearch ? "block" : "none";
      globalSearchNode.toggleAttribute("disabled", !showQuickSearch);
      if (!showQuickSearch) {
        globalSearchNode.value = "";
      }
    }
    if (searchPanelNode && !showQuickSearch) {
      searchPanelNode.style.display = "none";
      if (searchResultsNode) {
        searchResultsNode.innerHTML = "";
      }
    }
  }

  function syncShellControlsVisibility(viewName = currentView) {
    const showDashboardShellControls = isAuthenticated() && viewName === "dashboard";
    const showAdminApiSettings = showDashboardShellControls && isAdmin();
    const apiSection = document.getElementById("api-section");
    const sessionControls = document.getElementById("session-controls");
    const simPanel = document.getElementById("sim-panel");
    if (apiSection) {
      apiSection.style.display = showAdminApiSettings ? "flex" : "none";
    }
    if (sessionControls) {
      sessionControls.style.display = showDashboardShellControls ? "flex" : "none";
    }
    if (editApiKeyButton) {
      editApiKeyButton.style.display = showAdminApiSettings ? "inline-flex" : "none";
    }
    if (saveKeyButton) {
      saveKeyButton.style.display = showAdminApiSettings ? "inline-flex" : "none";
    }
    if (simPanel) {
      simPanel.style.display = showDashboardShellControls && isDemoMode ? "flex" : "none";
    }
    syncApiKeyField();
  }

  function showView(name) {
    console.log("SHOWVIEW_CALLED", name);
    if (!requireAuthenticatedUi()) {
      return;
    }
    currentView = name;
    state.currentView = name;
    setCurrentView(name);
    Object.entries(views).forEach(([key, v]) => {
      if (v) {
        v.style.display = "none";
        v.classList.toggle("active-view", key === name);
      }
    });

    if (views[name]) {
      views[name].style.display = "block";
    }

    document.querySelectorAll(".nav-item").forEach(btn => {
      btn.classList.toggle("active", btn.dataset.view === name);
    });

    syncSearchVisibility(name);
    syncShellControlsVisibility(name);

    switch (name) {
      case "investigations":
        renderInvestigationsView();
        break;
      case "hunt":
        renderHuntView();
        break;
      case "detection-rules":
        renderDetectionRulesView();
        break;
      case "cases":
        renderCasesView();
        break;
      case "activity":
        renderActivityView();
        loadOnlineUsers().catch(error => {
          console.error(error);
        });
        break;
      case "admin":
        renderAdminSocView();
        break;
      default:
        renderDashboardView();
        break;
    }
  }


  function highlightNewAlert(id) {
    const el = document.getElementById(`alert-${id}`);
    if (el) {
      highlight(el);
    }
  }

  function resetInvestigationFilters() {
    statsPanel.setFilters?.({
      severity: "all",
      ip: "",
      country: "",
      status: "all",
      attackType: "all",
      timeRange: "24h",
      sortBy: "time_desc"
    });
  }

  function openInvestigationAlert(id, { forceVisible = false } = {}) {
    if (!requireAuthenticatedUi()) {
      return;
    }
    const context = focusInvestigationContext(id);
    if (!context) {
      showToast("Alert not found");
      return;
    }
    if (forceVisible) {
      resetInvestigationFilters();
    }
    showView("investigations");
    statsPanel.selectAlert?.(context.selectedAlertId, { notifySelection: false });
    state.selectedAlertId = context.selectedAlertId;
    setSelectedAlertId(context.selectedAlertId);
    scrollSelectedInvestigationContext(context.selectedAlertId);
  }

  window.openInvestigation = function(id, options) {
    openInvestigationAlert(id, options || {});
  };

  window.__dashboardOnAlertSelected = alertId => {
    const frontendAlertId = getFrontendAlertId(alertId);
    state.selectedAlertId = frontendAlertId;
    setSelectedAlertId(frontendAlertId);
    const alert = findAlertByAnyId(frontendAlertId);
    if (alert?.sourceIp) {
      state.selectedEntity = String(alert.sourceIp);
      setSelectedEntityKey(state.selectedEntity);
    }
  };


  document.querySelectorAll(".nav-item").forEach(btn => {
    btn.onclick = () => {
      if (!requireAuthenticatedUi()) {
        return;
      }
      showView(btn.dataset.view);
    };
  });

  document.addEventListener("click", event => {
    const trigger = event.target.closest("[data-ioc-pivot-value]");
    if (!trigger) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    openIocPivot(
      trigger.getAttribute("data-ioc-pivot-type"),
      trigger.getAttribute("data-ioc-pivot-value"),
      state.currentView || workbenchState.currentView || "dashboard"
    );
  });



  function renderAdminList(node, rows, emptyMessage) {
    if (!node) {
      return;
    }
    if (!rows.length) {
      node.innerHTML = `<div class="detail-empty-inline">${escapeHtml(emptyMessage)}</div>`;
      return;
    }
    node.innerHTML = rows.join("");
  }

  function renderAdminSocView() {
    if (!isAdmin()) {
      return;
    }

    const snapshot = statsPanel.getSnapshot();
    const alerts = Array.isArray(snapshot.recentAlerts) ? snapshot.recentAlerts : [];
    const blockedIps = getBlockedIps();
    const recentExecutions = playbookExecutions.slice(0, 5);
    const recentActivity = selectGlobalActivityStream(state).slice(0, 5);
    const activeInvestigationCount = activeInvestigations.size;
    const activeCaseCount = casesCache.filter(entry => CASE_ACTIVE_STATUSES.includes(normalizeCaseStatus(entry?.status))).length;
    const ruleCount = detectionRules.length || Object.keys(rulesConfig || {}).length;

    renderAdminList(
      presencePanelNode,
      [
        `<div class="admin-row"><strong>Active investigations</strong><span>${escapeHtml(String(activeInvestigationCount))}</span></div>`,
        `<div class="admin-row"><strong>Active cases</strong><span>${escapeHtml(String(activeCaseCount))}</span></div>`,
        `<div class="admin-row"><strong>Blocked IPs</strong><span>${escapeHtml(String(blockedIps.length))}</span></div>`,
        ...adminPresenceUsers.map(entry => {
        const user = entry && typeof entry === "object" ? entry : { username: String(entry || "Unknown"), role: "user" };
        return `
          <div class="admin-row">
            <strong>${escapeHtml(user.username || "Unknown")}</strong>
            <span>${escapeHtml(user.current_page ? `${user.role || "user"} · ${user.current_page}` : (user.role || "user"))}</span>
          </div>
        `;
      })],
      "No analysts online."
    );

    renderAdminList(
      typingPanelNode,
      [
        ...[...activeInvestigations.values()]
        .sort((left, right) => Number(right.timestamp || 0) - Number(left.timestamp || 0))
        .slice(0, 8)
        .map(entry => `
          <div class="admin-row">
            <strong>${escapeHtml(entry.user)}</strong>
            <span>${escapeHtml(entry.alertId)}</span>
          </div>
        `),
        ...recentActivity.map(entry => `
          <div class="admin-row">
            <strong>${escapeHtml(entry.actor || entry.user || "system")}</strong>
            <span>${escapeHtml(entry.message || entry.action || "Activity")}</span>
          </div>
        `)
      ],
      "No active investigations."
    );

    renderAdminList(
      slaPanelNode,
      [
        `<div class="admin-row"><strong>SLA Compliance</strong><span>${escapeHtml(String(snapshot.slaCompliancePercent ?? 100))}%</span></div>`,
        `<div class="admin-row"><strong>Recent alerts</strong><span>${escapeHtml(String(alerts.length))}</span></div>`,
        ...alerts.slice(0, 8).map(alert => {
          const label = alert.overdue || alert.slaBreaches?.ack || alert.slaBreaches?.close ? "BREACH" : "OK";
          return `
            <div class="admin-row">
              <strong>${escapeHtml(alert.sourceIp || "unknown")}</strong>
              <span>${escapeHtml(label)}</span>
            </div>
          `;
        })
      ],
      "No alerts in scope."
    );

    if (rulesPanelNode) {
      const entries = detectionRules.length
        ? detectionRules.map(rule => [rule.key, rule])
        : Object.entries(rulesConfig);
      if (!entries.length) {
        rulesPanelNode.innerHTML = `<div class="detail-empty-inline">${escapeHtml(state.mode === "demo" || !state.apiKey ? "Demo rule cards appear here after local rules load." : "Rule configuration is unavailable.")}</div>`;
      } else {
        rulesPanelNode.innerHTML = `
          <div class="admin-row"><strong>Rule count</strong><span>${escapeHtml(String(ruleCount))}</span></div>
          ${entries.slice(0, 5).map(([rule, configEntry]) => {
          const config = configEntry && typeof configEntry === "object" ? configEntry : {};
          return `
            <div class="admin-row admin-row-block">
              <strong>${escapeHtml(config.name || rule)}</strong>
              <span>${escapeHtml(config.attack_type || "Detection rule")}</span>
              <span>${escapeHtml(config.enabled === false ? "Disabled" : "Enabled")} · ${escapeHtml(String(config.severity || "medium").toUpperCase())}</span>
              <span>${escapeHtml(config.mitre_mapping?.id || "No MITRE")} · ${escapeHtml(config.last_triggered ? formatAbsoluteTime(config.last_triggered) : "Never triggered")}</span>
            </div>
          `;
        }).join("")}`;
      }
    }

    renderAdminList(
      playbooksPanelNode,
      [
        `<div class="admin-row"><strong>Recent playbook executions</strong><span>${escapeHtml(String(recentExecutions.length))}</span></div>`,
        ...recentExecutions.map(execution => {
          const impacted = (Array.isArray(execution.steps) ? execution.steps : [])
            .map(step => getPlaybookStepResultValue(step, ["ip", "caseId", "case_id", "assignedTo"]))
            .filter(Boolean)
            .join(" · ");
        return `
          <div class="admin-row admin-row-block">
            <strong>${escapeHtml(execution.playbook_key || execution.playbook_id || "Playbook")}</strong>
            <span>${escapeHtml(execution.automatic ? "Automatic" : "Manual")} · ${escapeHtml(execution.status || "success")}</span>
            <span>${escapeHtml(impacted || "No affected entities recorded")}</span>
            <span>${escapeHtml(formatAbsoluteTime(execution.completed_at || execution.started_at || 0))}</span>
          </div>
        `;
      })],
      "No playbooks loaded."
    );
  }

  async function sendPresenceHeartbeat() {
    if (!state.user?.username || !state.apiKey || state.mode === "demo") {
      return;
    }
    await fetch(`${config.apiBaseUrl.replace(/\/+$/, "")}/auth/heartbeat`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": state.apiKey,
        "X-User": state.user.username
      },
      body: JSON.stringify({
        current_page: state.currentView || workbenchState.currentView || "dashboard"
      })
    });
  }

  function renderOnlineUsersPanel() {
    if (!activityOnlineUsersNode || !activityOnlineStatusNode || !activityOnlineCountNode) {
      return;
    }

    const fallbackUsers = state.mode === "demo" && state.user?.username ? [{
      username: state.user.username,
      role: state.user.role,
      status: "online",
      last_seen: Date.now() / 1000,
      current_page: state.currentView || "activity"
    }] : [];
    const users = (Array.isArray(state.onlineUsers) && state.onlineUsers.length ? state.onlineUsers : fallbackUsers)
      .slice()
      .sort((left, right) => String(left.username || "").localeCompare(String(right.username || "")));

    activityOnlineCountNode.textContent = `(${users.length})`;
    activityOnlineStatusNode.textContent = users.length ? "Currently active" : "No users online";
    activityOnlineUsersNode.innerHTML = users.length ? users.map(user => {
      const isCurrentUser = user.username === state.user?.username;
      return `
        <div class="activity-online-user${isCurrentUser ? " is-current-user" : ""}">
          <div class="activity-online-user-main">
            <span class="activity-online-dot" aria-hidden="true"></span>
            <strong>${escapeHtml(isCurrentUser ? `${user.username} (You)` : (user.username || "Unknown"))}</strong>
          </div>
          <div class="activity-online-user-meta">
            <span>${escapeHtml(String(user.role || "user").toUpperCase())}</span>
            <span>${escapeHtml(user.current_page ? `active on ${user.current_page}` : "active now")}</span>
          </div>
        </div>
      `;
    }).join("") : '<div class="detail-empty-inline">No users online.</div>';
  }

  async function loadOnlineUsers() {
    if (!state.user?.username || !state.apiKey || state.mode === "demo") {
      state.onlineUsers = state.mode === "demo" && state.user?.username ? [{
        username: state.user.username,
        role: state.user.role,
        status: "online",
        last_seen: Date.now() / 1000,
        current_page: state.currentView || "activity"
      }] : [];
      if (state.currentView === "activity") {
        renderOnlineUsersPanel();
      }
      return;
    }

    const response = await fetch(`${config.apiBaseUrl.replace(/\/+$/, "")}/activity/online-users?current_page=${encodeURIComponent(state.currentView || workbenchState.currentView || "dashboard")}`, {
      headers: {
        "X-API-Key": state.apiKey,
        "X-User": state.user.username
      }
    });
    const payload = await response.json().catch(() => ({ users: [] }));
    if (!response.ok) {
      throw new Error(payload?.detail || "Failed to load online users");
    }
    state.onlineUsers = Array.isArray(payload.users) ? payload.users : [];
    if (state.currentView === "activity") {
      renderOnlineUsersPanel();
    }
  }

  async function loadAdminPresence() {
    if (!isAdmin() || !state.apiKey || !state.user?.username || state.mode === "demo") {
      adminPresenceUsers = [];
      renderAdminSocView();
      return;
    }

    const response = await fetch(`${config.apiBaseUrl.replace(/\/+$/, "")}/admin/presence`, {
      headers: {
        "X-API-Key": state.apiKey,
        "X-User": state.user.username
      }
    });
    const payload = await response.json().catch(() => ({ users: [] }));
    if (!response.ok) {
      throw new Error(payload?.detail || "Failed to load presence");
    }
    adminPresenceUsers = Array.isArray(payload.users) ? payload.users : [];
    renderAdminSocView();
  }

  async function loadRulesConfig() {
    if (!isAdmin() || !state.apiKey || !state.user?.username || state.mode === "demo") {
      rulesConfig = {};
      renderAdminSocView();
      return;
    }

    const response = await fetch(`${config.apiBaseUrl.replace(/\/+$/, "")}/rules`, {
      headers: {
        "X-API-Key": state.apiKey,
        "X-User": state.user.username
      }
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload?.detail || "Failed to load rules");
    }
    rulesConfig = payload && typeof payload === "object" ? payload : {};
    renderAdminSocView();
  }

  function getDemoDetectionRules() {
    return [
      {
        key: "credential_stuffing",
        name: "Credential Stuffing",
        attack_type: "credential_stuffing",
        severity: "high",
        enabled: true,
        mitre_mapping: { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
        threshold: 10,
        time_window_seconds: 60,
        user_threshold: 10,
        device_threshold: 10,
        last_triggered: Date.now() / 1000 - 120,
      },
      {
        key: "streaming_fraud",
        name: "Streaming Fraud",
        attack_type: "streaming_fraud",
        severity: "medium",
        enabled: true,
        mitre_mapping: { id: "T1498", name: "Network Denial of Service", tactic: "Impact" },
        threshold: 50,
        time_window_seconds: 300,
        user_threshold: 50,
        device_threshold: 50,
        last_triggered: Date.now() / 1000 - 3600,
      },
      {
        key: "device_abuse",
        name: "Device Abuse",
        attack_type: "device_abuse",
        severity: "high",
        enabled: true,
        mitre_mapping: { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" },
        threshold: 5,
        time_window_seconds: 600,
        user_threshold: 5,
        device_threshold: 5,
        last_triggered: Date.now() / 1000 - 900,
      },
      {
        key: "rate_limit_abuse",
        name: "Rate Limit Abuse",
        attack_type: "rate_limit_abuse",
        severity: "high",
        enabled: true,
        mitre_mapping: { id: "T1499", name: "Endpoint Denial of Service", tactic: "Impact" },
        threshold: 25,
        time_window_seconds: 60,
        user_threshold: 20,
        device_threshold: 20,
        last_triggered: Date.now() / 1000 - 300,
      }
    ];
  }

  async function loadDetectionRules() {
    if (state.mode === "demo" || !state.apiKey) {
      detectionRules = getDemoDetectionRules();
      if (!selectedDetectionRuleKey && detectionRules.length) {
        selectedDetectionRuleKey = detectionRules[0].key;
      }
      renderDetectionRulesView();
      return;
    }
    const payload = await requestJson("/rules/detection");
    detectionRules = Array.isArray(payload.rules) ? payload.rules : [];
    if (!selectedDetectionRuleKey && detectionRules.length) {
      selectedDetectionRuleKey = detectionRules[0].key;
    }
    renderDetectionRulesView();
  }

  function getSelectedDetectionRule() {
    return detectionRules.find(rule => String(rule.key) === String(selectedDetectionRuleKey)) || detectionRules[0] || null;
  }

  function renderDetectionRulesView() {
    if (detectionRulesStatusNode) {
      detectionRulesStatusNode.textContent = detectionRules.length
        ? `${detectionRules.length} ${state.mode === "demo" || !state.apiKey ? "demo" : "live"} rules loaded`
        : (state.mode === "demo" || !state.apiKey ? "Demo mode: sample rules unavailable" : "No rules loaded");
    }
    if (detectionRulesListNode) {
      if (!detectionRules.length) {
        detectionRulesListNode.innerHTML = `<div class="detail-empty-inline">${escapeHtml(state.mode === "demo" || !state.apiKey ? "Demo rules are unavailable right now. Reload demo mode to repopulate sample detections." : "Detection rules could not be loaded from the backend.")}</div>`;
      } else {
        detectionRulesListNode.innerHTML = `
          <div class="panel-note detection-rules-banner">${escapeHtml(state.mode === "demo" || !state.apiKey ? "Demo mode uses local sample rules. Changes are safe and remain local to this session." : "Connected to the live rule store.")}</div>
          ${detectionRules.map(rule => `
          <button type="button" class="case-card detection-rule-card${String(rule.key) === String(selectedDetectionRuleKey) ? " is-selected" : ""}" data-detection-rule-key="${escapeHtml(String(rule.key))}">
            <div class="case-card-top">
              <strong>${escapeHtml(rule.name || rule.key)}</strong>
              ${renderSeverityChip(rule.severity || "medium")}
            </div>
            <div class="case-card-meta"><span>${escapeHtml(rule.attack_type || rule.key)}</span><span>${escapeHtml(rule.enabled ? "Enabled" : "Disabled")}</span></div>
            <div class="case-card-meta"><span>${escapeHtml(rule.mitre_mapping?.id || "No MITRE")}</span><span>${escapeHtml(rule.last_triggered ? formatAbsoluteTime(rule.last_triggered) : "Never triggered")}</span></div>
          </button>
        `).join("")}`;
        detectionRulesListNode.querySelectorAll("[data-detection-rule-key]").forEach(button => {
          button.addEventListener("click", () => {
            selectedDetectionRuleKey = button.getAttribute("data-detection-rule-key");
            renderDetectionRulesView();
          });
        });
      }
    }

    const rule = getSelectedDetectionRule();
    if (!detectionRuleEditorNode || !detectionRuleEditorStatusNode) {
      return;
    }
    if (!rule) {
      detectionRuleEditorStatusNode.textContent = "Select a rule";
      detectionRuleEditorNode.className = "detail-empty";
      detectionRuleEditorNode.textContent = "Choose a rule to edit detection logic and run tests.";
      return;
    }

    detectionRuleEditorStatusNode.textContent = rule.name || rule.key;
    detectionRuleEditorNode.className = "detail-panel";
    detectionRuleEditorNode.innerHTML = `
      <div class="detail-section enrichment-section">
        <strong>Rule Settings</strong>
        <div class="detail-grid">
          <label class="field"><span>Rule name</span><input id="rule-editor-name" type="text" value="${escapeHtml(rule.name || "")}"></label>
          <label class="field"><span>Attack type</span><input id="rule-editor-attack-type" type="text" value="${escapeHtml(rule.attack_type || "")}"></label>
          <label class="field"><span>Severity</span>
            <select id="rule-editor-severity">
              ${["low", "medium", "high", "critical"].map(value => `<option value="${value}"${String(rule.severity) === value ? " selected" : ""}>${value.toUpperCase()}</option>`).join("")}
            </select>
          </label>
          <label class="field"><span>Enabled</span><input id="rule-editor-enabled" type="checkbox"${rule.enabled ? " checked" : ""}></label>
          <label class="field"><span>Threshold</span><input id="rule-editor-threshold" type="number" value="${escapeHtml(String(rule.threshold ?? 0))}"></label>
          <label class="field"><span>Time window (sec)</span><input id="rule-editor-time-window" type="number" value="${escapeHtml(String(rule.time_window_seconds ?? 60))}"></label>
          <label class="field"><span>User threshold</span><input id="rule-editor-user-threshold" type="number" value="${escapeHtml(String(rule.user_threshold ?? rule.threshold ?? 0))}"></label>
          <label class="field"><span>Device threshold</span><input id="rule-editor-device-threshold" type="number" value="${escapeHtml(String(rule.device_threshold ?? rule.threshold ?? 0))}"></label>
          <label class="field"><span>MITRE ID</span><input id="rule-editor-mitre-id" type="text" value="${escapeHtml(rule.mitre_mapping?.id || "")}"></label>
          <label class="field"><span>MITRE Name</span><input id="rule-editor-mitre-name" type="text" value="${escapeHtml(rule.mitre_mapping?.name || "")}"></label>
          <label class="field"><span>MITRE Tactic</span><input id="rule-editor-mitre-tactic" type="text" value="${escapeHtml(rule.mitre_mapping?.tactic || "")}"></label>
        </div>
        <div class="playbook-controls">
          <button class="button" type="button" id="save-detection-rule">Save Rule</button>
          <button class="button button-secondary" type="button" id="test-detection-rule">Test Rule</button>
          <span class="panel-note">Last triggered: ${escapeHtml(rule.last_triggered ? formatAbsoluteTime(rule.last_triggered) : "Never")}</span>
        </div>
        <div id="rule-test-result" class="panel-note"></div>
      </div>
    `;
    detectionRuleEditorNode.querySelector("#save-detection-rule")?.addEventListener("click", () => {
      window.saveDetectionRule?.(rule.key);
    });
    detectionRuleEditorNode.querySelector("#test-detection-rule")?.addEventListener("click", () => {
      window.testDetectionRule?.(rule.key);
    });
  }

  function stopSocLiveView() {
    if (presenceHeartbeatInterval) {
      window.clearInterval(presenceHeartbeatInterval);
      presenceHeartbeatInterval = null;
    }
    if (adminPresencePollInterval) {
      window.clearInterval(adminPresencePollInterval);
      adminPresencePollInterval = null;
    }
    activeInvestigations = new Map();
    adminPresenceUsers = [];
    state.onlineUsers = [];
    rulesConfig = {};
    detectionRules = [];
    selectedDetectionRuleKey = "";
    renderAdminSocView();
    renderDetectionRulesView();
    renderOnlineUsersPanel();
  }

  function startSocLiveView() {
    stopSocLiveView();
    if (!state.user?.username || state.mode === "demo") {
      return;
    }

    sendPresenceHeartbeat().catch(() => {});
    loadOnlineUsers().catch(() => {});
    presenceHeartbeatInterval = window.setInterval(() => {
      sendPresenceHeartbeat().catch(() => {});
      loadOnlineUsers().catch(() => {});
    }, 30000);

    if (!isAdmin()) {
      return;
    }

    loadAdminPresence().catch(() => {});
    adminPresencePollInterval = window.setInterval(() => {
      loadAdminPresence().catch(() => {});
    }, 30000);
    loadRulesConfig().catch(() => {});
    loadDetectionRules().catch(() => {});
  }

  window.saveRuleConfig = async rule => {
    try {
      requireAuth();
      requireAdmin();
    } catch {
      return;
    }

    const current = rulesConfig?.[rule];
    if (!current || typeof current !== "object") {
      return;
    }

    const updates = Object.fromEntries(
      Object.entries(current)
        .filter(([, value]) => typeof value === "number")
        .map(([key]) => {
          const node = document.getElementById(`rule-${rule}-${key}`);
          return [key, Number(node?.value ?? current[key])];
        })
        .filter(([, value]) => Number.isFinite(value))
    );

    const response = await fetch(`${config.apiBaseUrl.replace(/\/+$/, "")}/rules/update`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": state.apiKey,
        "X-User": state.user.username
      },
      body: JSON.stringify({ rule, config: updates })
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload?.status !== "success") {
      window.alert(payload?.message || payload?.detail || "Failed to update rule");
      return;
    }

    rulesConfig[rule] = payload.config || updates;
    renderAdminSocView();
    window.alert(`Updated ${rule}`);
  };

  function readDetectionRuleEditorValues(currentRule) {
    return {
      name: document.getElementById("rule-editor-name")?.value || currentRule.name,
      attack_type: document.getElementById("rule-editor-attack-type")?.value || currentRule.attack_type,
      severity: document.getElementById("rule-editor-severity")?.value || currentRule.severity,
      enabled: Boolean(document.getElementById("rule-editor-enabled")?.checked),
      threshold: Number(document.getElementById("rule-editor-threshold")?.value ?? currentRule.threshold) || currentRule.threshold,
      time_window_seconds: Number(document.getElementById("rule-editor-time-window")?.value ?? currentRule.time_window_seconds) || currentRule.time_window_seconds,
      user_threshold: Number(document.getElementById("rule-editor-user-threshold")?.value ?? currentRule.user_threshold) || currentRule.user_threshold,
      device_threshold: Number(document.getElementById("rule-editor-device-threshold")?.value ?? currentRule.device_threshold) || currentRule.device_threshold,
      mitre_mapping: {
        id: document.getElementById("rule-editor-mitre-id")?.value || currentRule.mitre_mapping?.id || "",
        name: document.getElementById("rule-editor-mitre-name")?.value || currentRule.mitre_mapping?.name || "",
        tactic: document.getElementById("rule-editor-mitre-tactic")?.value || currentRule.mitre_mapping?.tactic || "",
      }
    };
  }

  window.saveDetectionRule = async ruleKey => {
    const currentRule = detectionRules.find(rule => String(rule.key) === String(ruleKey));
    if (!currentRule) {
      return;
    }
    const nextRule = { ...currentRule, ...readDetectionRuleEditorValues(currentRule) };
    if (state.mode === "demo" || !state.apiKey) {
      detectionRules = detectionRules.map(rule => String(rule.key) === String(ruleKey) ? nextRule : rule);
      renderDetectionRulesView();
      showToast(`Updated ${nextRule.name}`);
      return;
    }
    try {
      const payload = await requestJson("/rules/detection/update", {
        method: "POST",
        body: JSON.stringify({ rule_key: ruleKey, rule: nextRule })
      });
      detectionRules = detectionRules.map(rule => String(rule.key) === String(ruleKey) ? payload.rule : rule);
      renderDetectionRulesView();
      showToast(`Updated ${payload.rule.name}`);
      await loadSnapshot("manual");
    } catch (error) {
      console.error(error);
      showToast(error.message || "Failed to update rule");
    }
  };

  window.testDetectionRule = async ruleKey => {
    const currentRule = detectionRules.find(rule => String(rule.key) === String(ruleKey));
    if (!currentRule) {
      return;
    }
    const outputNode = document.getElementById("rule-test-result");
    if (state.mode === "demo" || !state.apiKey) {
      const matches = (Array.isArray(state.alerts) ? state.alerts : []).filter(alert =>
        String(alert.attackType || alert.attack_type || alert.rule || "").toLowerCase() === String(currentRule.attack_type || "").toLowerCase()
      ).length;
      if (outputNode) {
        outputNode.textContent = `Test result: ${matches} matching demo alerts`;
      }
      showToast(`Rule test returned ${matches} matches`);
      return;
    }
    try {
      const payload = await requestJson("/rules/test", {
        method: "POST",
        body: JSON.stringify({ rule_key: ruleKey })
      });
      if (outputNode) {
        outputNode.textContent = `Test result: ${payload.matches} matches in recent data`;
      }
      showToast(`Rule test returned ${payload.matches} matches`);
    } catch (error) {
      console.error(error);
      if (outputNode) {
        outputNode.textContent = error.message || "Rule test failed";
      }
    }
  };

  let countdownSeconds = 15;
  let liveStream = null;
  let isSnapshotRefreshing = false;
  let casesCache = [];
  let investigationsCache = [];
  let selectedCaseId = workbenchState.selectedCaseId;
  let selectedCaseQueue = [];
  let selectedCaseTab = "active";
  let selectedCaseWorkspaceTab = "overview";
  let openCaseMoreActionsId = null;
  let suppressCaseAutoSelect = false;
  let caseQueueCompletionMessage = "";
  let pendingQueuedCaseId = null;
  let pendingDeepLinkCaseId = getCaseIdFromUrl();
  let missingCaseToastId = "";
  let suppressCaseAutoNavigation = false;
  const CASE_ACTIVE_STATUSES = ["open", "in_progress", "contained", "resolved"];
  const CASE_WORKSPACE_TABS = ["overview", "evidence", "timeline", "related_alerts", "notes"];
  const CASE_STATUS_LABELS = {
    open: "Open",
    in_progress: "In Progress",
    contained: "Contained",
    resolved: "Resolved",
    closed: "Closed"
  };

  function normalizeCaseStatus(status) {
    const value = String(status || "open").toLowerCase();
    if (value === "investigating") {
      return "in_progress";
    }
    if (value === "escalated" || value === "linked") {
      return "contained";
    }
    return CASE_STATUS_LABELS[value] ? value : "open";
  }

  function syncSelectedCaseQueue() {
    selectedCaseQueue = syncCaseQueue(
      selectedCaseQueue,
      casesCache.map(entry => ({ ...entry, status: normalizeCaseStatus(entry.status) })),
      CASE_ACTIVE_STATUSES
    );
  }

  function getQueuedNextCaseId(currentCaseId = null) {
    syncSelectedCaseQueue();
    return getNextQueuedCaseId(selectedCaseQueue, currentCaseId);
  }

  function setCurrentCaseSelection(caseId, { suppressAutoSelect = false, preserveWorkspaceTab = false } = {}) {
    const previousSelectedCaseId = selectedCaseId;
    selectedCaseId = caseId ? String(caseId) : null;
    if (previousSelectedCaseId && previousSelectedCaseId !== selectedCaseId) {
      delete pendingCaseAssigneeSelections[previousSelectedCaseId];
    }
    if (!preserveWorkspaceTab) {
      selectedCaseWorkspaceTab = "overview";
    }
    setSelectedCaseId(selectedCaseId);
    suppressCaseAutoSelect = suppressAutoSelect;
    if (selectedCaseId) {
      pendingQueuedCaseId = selectedCaseId;
    }
    syncCaseQueueState();
    syncCaseDeepLink(selectedCaseId, { replace: previousSelectedCaseId === selectedCaseId });
  }

  async function openCaseWorkspace(caseId, { preserveWorkspaceTab = true } = {}) {
    const normalizedCaseId = String(caseId || "").trim();
    if (!normalizedCaseId) {
      showToast("Case not found");
      return false;
    }
    if (!casesCache.some(entry => String(entry?.id || "") === normalizedCaseId) && state.mode !== "demo" && state.apiKey) {
      await loadCases().catch(() => {});
    }
    const matchedCase = casesCache.find(entry => String(entry?.id || "") === normalizedCaseId) || null;
    if (!matchedCase) {
      showToast("Case not found");
      return false;
    }
    selectedCaseTab = normalizeCaseStatus(matchedCase.status) === "closed" ? "closed" : "active";
    setCurrentCaseSelection(normalizedCaseId, { preserveWorkspaceTab });
    showView("cases");
    renderCasesView();
    return true;
  }

  function syncCaseDeepLink(caseId, { replace = false } = {}) {
    const currentCaseId = getCaseIdFromUrl();
    const nextCaseId = caseId ? String(caseId) : "";
    if (currentCaseId === nextCaseId) {
      return;
    }
    const nextUrl = buildCaseDeepLinkUrl(nextCaseId);
    const nextState = {
      ...(history.state && typeof history.state === "object" ? history.state : {}),
      caseId: nextCaseId || null
    };
    if (replace) {
      window.history.replaceState(nextState, "", nextUrl);
      return;
    }
    window.history.pushState(nextState, "", nextUrl);
  }

  function applyPendingCaseDeepLink({ notifyIfMissing = false } = {}) {
    const requestedCaseId = pendingDeepLinkCaseId ? String(pendingDeepLinkCaseId) : "";
    if (!requestedCaseId) {
      missingCaseToastId = "";
      return false;
    }

    const matchingCase = casesCache.find(entry => String(entry.id) === requestedCaseId) || null;
    if (matchingCase) {
      missingCaseToastId = "";
      pendingDeepLinkCaseId = "";
      setCurrentCaseSelection(matchingCase.id, { preserveWorkspaceTab: true });
      if (state.currentView !== "cases") {
        showView("cases");
      }
      return true;
    }

    if (notifyIfMissing && missingCaseToastId !== requestedCaseId) {
      showToast("Case not found");
      missingCaseToastId = requestedCaseId;
    }
    pendingDeepLinkCaseId = "";
    syncCaseDeepLink(null, { replace: true });
    return false;
  }

  function toggleQueuedCase(caseId, isSelected) {
    const normalizedCaseId = String(caseId || "");
    if (!normalizedCaseId) {
      return;
    }
    syncSelectedCaseQueue();
    selectedCaseQueue = toggleCaseQueue(selectedCaseQueue, normalizedCaseId, isSelected);
    if (isSelected) {
      if (!selectedCaseId) {
        setCurrentCaseSelection(normalizedCaseId);
      }
      return;
    }
    if (selectedCaseId === normalizedCaseId) {
      const nextCaseId = getQueuedNextCaseId(normalizedCaseId);
      setCurrentCaseSelection(nextCaseId, { suppressAutoSelect: !nextCaseId });
    }
    syncCaseQueueState();
  }

  function normalizeCaseWorkspaceTab(tabName) {
    const normalizedTab = String(tabName || "overview").toLowerCase();
    return CASE_WORKSPACE_TABS.includes(normalizedTab) ? normalizedTab : "overview";
  }

  function setCaseWorkspaceTab(tabName) {
    selectedCaseWorkspaceTab = normalizeCaseWorkspaceTab(tabName);
    if (state.currentView === "cases") {
      renderCasesView();
    }
  }

  function getPlaybookExecutionsForAlert(alertId) {
    const normalizedAlertId = String(alertId || "");
    return playbookExecutions.filter(entry => String(entry.alert_id || "") === normalizedAlertId);
  }

  function getLatestPlaybookExecutionForAlert(alertId) {
    return getPlaybookExecutionsForAlert(alertId)
      .slice()
      .sort((left, right) => Number(right.completed_at || right.started_at || 0) - Number(left.completed_at || left.started_at || 0))[0] || null;
  }

  function getPlaybookExecutionsForCase(caseRecord) {
    const linkedAlertIds = new Set(
      [
        caseRecord?.source_alert_id,
        caseRecord?.alert_id,
        ...(Array.isArray(caseRecord?.linked_alert_ids) ? caseRecord.linked_alert_ids : []),
        ...getCaseLinkedAlerts(caseRecord).map(alert => alert?.id || alert?.alert_id || null)
      ]
        .filter(Boolean)
        .map(value => String(value))
    );
    return playbookExecutions.filter(entry => linkedAlertIds.has(String(entry.alert_id || "")));
  }

  function getPlaybookStepResultValue(step, keys = []) {
    if (!step || !step.result || typeof step.result !== "object") {
      return "";
    }
    for (const key of keys) {
      if (step.result[key]) {
        return String(step.result[key]);
      }
    }
    return "";
  }

  function getPlaybookRunState(alertRef, playbookKey = "", context = {}) {
    let alert = typeof alertRef === "object" && alertRef
      ? findAlertByAnyId(alertRef)
      : findAlertByAnyId(String(alertRef || ""));
    if (!alert?.id && context.caseRecord) {
      const resolvedAlertId = resolveCasePlaybookAlertId(context.caseRecord);
      if (resolvedAlertId) {
        alert = findAlertByAnyId(resolvedAlertId);
      }
    }
    const origin = String(context.origin || "investigations").toLowerCase();
    const playbook = getPlaybookByKey(playbookKey) || null;
    if (!alert?.id) {
      const reason = "Linked alert no longer exists for this playbook run.";
      console.warn("PLAYBOOK_RERUN_BLOCKED", { reason, origin, alertRef, playbookKey });
      return { canRun: false, reason, code: "missing_alert" };
    }

    const lifecycle = normalizeAlertLifecycle(alert);
    const disposition = String(alert.disposition || alert.alertDisposition || alert.alert_disposition || "").toLowerCase();
    if (lifecycle === "false_positive") {
      const reason = "Linked alert no longer eligible: alert is marked false positive.";
      console.warn("PLAYBOOK_RERUN_BLOCKED", { reason, origin, alertId: alert.id, playbookKey });
      return { canRun: false, reason, code: "false_positive" };
    }
    if (lifecycle === "closed") {
      const reason = "Linked alert no longer eligible: alert is closed.";
      console.warn("PLAYBOOK_RERUN_BLOCKED", { reason, origin, alertId: alert.id, playbookKey });
      return { canRun: false, reason, code: "closed" };
    }
    if (disposition === "suppressed") {
      const reason = "Linked alert no longer eligible: alert remains suppressed.";
      console.warn("PLAYBOOK_RERUN_BLOCKED", { reason, origin, alertId: alert.id, playbookKey });
      return { canRun: false, reason, code: "suppressed" };
    }

    const latestExecution = getLatestPlaybookExecutionForAlert(alert.id);
    const blockedIp = latestExecution?.steps
      ?.map(step => getPlaybookStepResultValue(step, ["ip"]))
      .find(Boolean) || getAlertPrimaryIp(alert);
    if (blockedIp && isIpCurrentlyBlocked(blockedIp)) {
      const reason = `Playbook already remediated IP ${blockedIp}. Unblock the IP before rerunning.`;
      console.warn("PLAYBOOK_RERUN_BLOCKED", { reason, origin, alertId: alert.id, playbookKey, blockedIp });
      return { canRun: false, reason, code: "ip_still_blocked", blockedIp };
    }

    if (latestExecution && blockedIp && lifecycle === "in_case") {
      const reason = `Previous remediation for ${blockedIp} was reversed. Case remains open, and rerun is available.`;
      return { canRun: true, reason, code: "rerun_reopened", blockedIp, playbook: playbook?.key || playbook?.id || "" };
    }

    return { canRun: true, reason: "", code: "ready", playbook: playbook?.key || playbook?.id || "" };
  }

  function appendDemoUnblockActivity(ip) {
    const linkedCases = casesCache.filter(caseRecord => {
      const linkedAlerts = getCaseLinkedAlerts(caseRecord);
      return linkedAlerts.some(alert => getAlertPrimaryIp(alert) === ip)
        || getCaseBlockableIp(caseRecord) === ip;
    });
    const timestamp = Date.now() / 1000;
    linkedCases.forEach(caseRecord => {
      const unblockAction = buildCaseAction(
        "unblock_ip",
        caseRecord,
        `${getCurrentActor()} unblocked IP ${ip} for case ${caseRecord.title || caseRecord.id}`,
        { ip },
        { ip, remediationReversed: true }
      );
      const unblockTimelineEvent = createCaseTimelineEntry("ip_unblocked", {
        ip,
        remediationReversed: true
      }, getCurrentActor(), timestamp);
      appendCaseActionToDemo(caseRecord.id, unblockAction, null, [unblockTimelineEvent]);
    });
  }

  window.__dashboardGetPlaybookRunState = (alertRef, playbookKey, context = {}) => getPlaybookRunState(alertRef, playbookKey, context);

  document.addEventListener("mousedown", event => {
    if (event.target.closest("select")) {
      isUserInteracting = true;
    }
  });

  document.addEventListener("keydown", event => {
    if (event.key === "Escape" && iocPivotState.open) {
      closeIocPivot();
    }
  });

  document.addEventListener("mouseup", () => {
    window.setTimeout(() => {
      isUserInteracting = false;
    }, 300);
  });

  function applyDemoAlertUpdate(updater) {
    let changed = false;
    currentDemoAlerts.forEach(alert => {
      const didChange = updater(alert);
      if (didChange) {
        changed = true;
      }
    });
    if (changed) {
      applyAlerts(currentDemoAlerts);
    }
    return changed;
  }

  function buildStaticDemoAlerts() {
    const anchor = Date.now();
    const newestTimestamp = Math.max(...demoAlerts.map(alert => Number(alert.timestamp) || anchor));

    return demoAlerts.map(alert => {
      const timestamp = Number(alert.timestamp) || newestTimestamp;
      return {
        ...alert,
        raw: alert.raw ? { ...alert.raw } : alert.raw,
        indicators: Array.isArray(alert.indicators) ? [...alert.indicators] : [],
        notes: Array.isArray(alert.notes) ? alert.notes.map(note => ({ ...note })) : [],
        riskHistory: Array.isArray(alert.riskHistory) ? alert.riskHistory.map(entry => ({ ...entry })) : [],
        timestamp: anchor - (newestTimestamp - timestamp)
      };
    });
  }

  function appendDemoAudit(action, target) {
    const actionEntry = dispatchSocAction({
      actionType: action,
      actor: currentUser?.username || state.user?.username || "Analyst",
      targetType: "alert",
      targetId: target,
      relatedAlertId: target,
      message: `${currentUser?.username || state.user?.username || "Analyst"} ${String(action).replace(/_/g, " ")} ${target}`
    }, { reflectActivity: false });
    demoAuditLogs = [...demoAuditLogs, actionEntry].slice(-100);
    statsPanel.setAuditLogs(demoAuditLogs);
    const activityEntry = toActivityEntry(actionEntry);
    if (activityEntry) {
      activityLogEntries = mergeActivityLogs(activityLogEntries, [activityEntry]);
      if (state.currentView === "activity") {
        renderActivityView();
      }
    }
  }

  window.__dashboardOnSelectAlert = alertId => {
    const frontendAlertId = getFrontendAlertId(alertId);
    applyWorkflowState(workflowCommands.selectAlert(state, frontendAlertId));
  };

  function setRefreshStatus(label, message, tone = "waiting") {
    if (refreshStatusNode) {
      refreshStatusNode.textContent = label;
    }
    if (refreshMessageNode) {
      refreshMessageNode.textContent = message;
    }
    if (refreshIndicatorNode) {
      refreshIndicatorNode.className = `refresh-indicator is-${tone}`;
    }
  }

  function setRefreshCountdown(label) {
    if (refreshCountdownNode) {
      refreshCountdownNode.textContent = label;
    }
  }

  function setRefreshButtonState(isEnabled) {
    if (refreshNowButton) {
      refreshNowButton.disabled = !isEnabled;
    }
  }

  function resetCountdown(seconds = 15) {
    countdownSeconds = seconds;
    setRefreshCountdown(`Next update in ${countdownSeconds}s`);
  }

  function setLastUpdated(timestamp = Date.now()) {
    if (lastUpdatedNode) {
      lastUpdatedNode.textContent = new Date(timestamp).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
      });
    }
  }

  function setLiveStatus(label) {
    if (liveStatusNode) {
      liveStatusNode.textContent = label;
    }
  }

  function setReportStatus(label) {
    if (reportStatusNode) {
      reportStatusNode.textContent = label;
    }
  }

  function updateUserUi() {
    if (currentUserNode) {
      currentUserNode.textContent = state.user ? `${state.user.username} (${state.user.role})` : "Not logged in";
    }
    if (userContainerNode) {
      userContainerNode.style.display = state.user ? "flex" : "none";
    }
    if (adminPanelNode) {
      adminPanelNode.style.display = state.user && isAdmin() ? "block" : "none";
    }

    const isAdminLocal = state.user?.role === "admin";
    document.querySelectorAll(".admin-only").forEach(el => {
      el.style.display = isAdminLocal ? "block" : "none";
    });

    if (state.user) {
      if (userAvatarNode) {
        userAvatarNode.textContent = getInitials(state.user.username);
      }
      if (userNameNode) {
        userNameNode.textContent = state.user.username;
      }
      if (userRoleNode) {
        userRoleNode.textContent = String(state.user.role || "").toUpperCase();
      }
    }
    document.querySelectorAll(".block-btn").forEach(button => {
      button.hidden = !isAdmin();
    });
    syncAuthGateUi();
    renderAdminSocView();
  }

  async function loginUser(username, password) {
    const makeLoginRequest = async (baseUrl) => {
      const response = await fetch(`${normalizeBaseUrl(baseUrl)}/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ username, password })
      });

      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload?.status !== "success") {
        throw new Error(payload?.message || "Login failed");
      }
      return payload;
    };

    const configuredBaseUrl = normalizeBaseUrl(config.apiBaseUrl);
    const defaultBaseUrl = normalizeBaseUrl(getDefaultApiBaseUrl());

    try {
      return await makeLoginRequest(configuredBaseUrl);
    } catch (error) {
      if (!configuredBaseUrl || configuredBaseUrl === defaultBaseUrl) {
        throw error;
      }
      const fallbackPayload = await makeLoginRequest(defaultBaseUrl);
      localStorage.setItem("cybermap.apiBaseUrl", defaultBaseUrl);
      config = { ...config, apiBaseUrl: defaultBaseUrl };
      if (endpointNode) {
        endpointNode.textContent = defaultBaseUrl;
      }
      setInputValue(apiBaseUrlInput, defaultBaseUrl);
      console.warn(`Login fallback succeeded against default backend ${defaultBaseUrl}; cleared stale configured endpoint ${configuredBaseUrl}.`);
      return fallbackPayload;
    }
  }

  async function loadAuditLogs() {
    if (state.mode === "demo") {
      statsPanel.setAuditLogs(demoAuditLogs);
      state.actionEvents = [...(Array.isArray(state.actionEvents) ? state.actionEvents : []), ...demoAuditLogs.map(parseActionEntry).filter(Boolean)];
      activityLogEntries = mergeActivityLogs(activityLogEntries, demoAuditLogs);
      if (state.currentView === "activity") {
        renderActivityView();
      }
      return;
    }
    if (!state.user?.username || !state.apiKey) {
      statsPanel.setAuditLogs([]);
      return;
    }

    try {
      const response = await apiFetch(`${config.apiBaseUrl.replace(/\/+$/, "")}/audit`);
      const payload = await response.json().catch(() => ({ logs: [] }));
      if (!response.ok) {
        throw new Error(payload?.detail || "Failed to load audit logs");
      }
      const logs = Array.isArray(payload.logs) ? payload.logs : [];
      statsPanel.setAuditLogs(logs);
      state.actionEvents = [...(Array.isArray(state.actionEvents) ? state.actionEvents : []), ...logs.map(parseActionEntry).filter(Boolean)];
      activityLogEntries = mergeActivityLogs(activityLogEntries, logs);
      if (state.currentView === "activity") {
        renderActivityView();
      }
    } catch (error) {
      if (state.mode === "live") {
        console.error("Audit log error:", error);
        statsPanel.setAuditLogs([]);
      }
    }
  }

  function normalizeBaseUrl(value) {
    return String(value || "").trim().replace(/\/+$/, "");
  }

  function formatRelativeTime(timestamp) {
    const value = Number(timestamp || 0) * (Number(timestamp || 0) < 9_999_999_999 ? 1000 : 1);
    if (!Number.isFinite(value) || value <= 0) {
      return "Unknown";
    }

    const deltaSeconds = Math.max(0, Math.round((Date.now() - value) / 1000));
    if (deltaSeconds < 60) {
      return `${deltaSeconds}s ago`;
    }
    if (deltaSeconds < 3600) {
      return `${Math.floor(deltaSeconds / 60)}m ago`;
    }
    return `${Math.floor(deltaSeconds / 3600)}h ago`;
  }

  async function requestJson(path, options = {}) {
    const url = `${normalizeBaseUrl(config.apiBaseUrl)}${path}`;
    const response = options.public
      ? await fetch(url, options)
      : await apiFetch(url, options);
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload?.detail || payload?.message || `Request failed: ${response.status}`);
    }
    return payload;
  }

  function ensureEntityProfileModal() {
    let modal = document.getElementById("entity-profile-modal");
    if (modal) {
      return modal;
    }
    modal = document.createElement("div");
    modal.id = "entity-profile-modal";
    modal.className = "entity-profile-modal";
    modal.hidden = true;
    modal.innerHTML = `
      <div class="entity-profile-backdrop" data-entity-close="true"></div>
      <div class="entity-profile-sheet" role="dialog" aria-modal="true" aria-label="Entity profile">
        <button type="button" class="entity-profile-close" data-entity-close="true">Close</button>
        <div class="entity-profile-body"></div>
      </div>
    `;
    modal.addEventListener("click", event => {
      const target = event.target;
      if (target instanceof HTMLElement && target.closest("[data-entity-close='true']")) {
        modal.hidden = true;
      }
    });
    document.body.appendChild(modal);
    return modal;
  }

  function buildLocalEntityPayload(entityType, entityKey) {
    const alerts = (Array.isArray(state.alerts) ? state.alerts : []).filter(alert =>
      extractAlertEntities(alert).some(entity =>
        entity.type === entityType && String(entity.value || "").toLowerCase() === String(entityKey || "").toLowerCase()
      )
    );
    const entity = alerts.flatMap(extractAlertEntities).find(candidate =>
      candidate.type === entityType && String(candidate.value || "").toLowerCase() === String(entityKey || "").toLowerCase()
    );
    return {
      profile: buildEntityProfile(entity || { type: entityType, value: entityKey, assetCriticality: "medium" }, alerts),
      recent_alerts: alerts
        .sort((left, right) => Number(right.timestamp || 0) - Number(left.timestamp || 0))
        .slice(0, 8)
    };
  }

  function renderEntityProfileModal(payload) {
    const modal = ensureEntityProfileModal();
    const body = modal.querySelector(".entity-profile-body");
    const profile = payload?.profile || {};
    const recentAlerts = Array.isArray(payload?.recent_alerts) ? payload.recent_alerts : [];
    if (!body) {
      return;
    }
    body.innerHTML = `
      <div class="entity-profile-header">
        <div>
          <div class="entity-profile-kind">${escapeHtml(String(profile.entity_type || "entity").toUpperCase())}</div>
          <h3>${escapeHtml(profile.display_name || profile.entity_key || "Unknown entity")}</h3>
        </div>
        <div class="entity-profile-risk">
          <span>Risk</span>
          <strong>${escapeHtml(String(profile.risk_score || 0))}</strong>
        </div>
      </div>
      <div class="entity-profile-summary">
        <span>${escapeHtml(String(profile.alert_count || 0))} alerts</span>
        <span>${escapeHtml(String(profile.case_count || 0))} cases</span>
        <span>Criticality ${escapeHtml(String(profile.asset_criticality || "medium").toUpperCase())}</span>
        <span>First seen ${escapeHtml(profile.first_seen ? new Date(profile.first_seen).toLocaleString() : "Unknown")}</span>
        <span>Last seen ${escapeHtml(profile.last_seen ? new Date(profile.last_seen).toLocaleString() : "Unknown")}</span>
      </div>
      <div class="attack-type-list">
        ${(Array.isArray(profile.related_attack_types) ? profile.related_attack_types : []).map(type => `<span class="attack-type-chip">${escapeHtml(type)}</span>`).join("")}
      </div>
      <div class="entity-profile-enrichment">
        <span>Geo: ${escapeHtml(profile.enrichment?.geo?.location || profile.enrichment?.geo?.country || "Unknown")}</span>
        <span>ASN: ${escapeHtml(profile.enrichment?.asn || "Unknown")}</span>
        <span>Reputation: ${escapeHtml(String(profile.enrichment?.reputation?.score ?? profile.risk_score ?? 0))}</span>
      </div>
      <div class="entity-profile-alerts">
        <strong>Recent alerts</strong>
        ${recentAlerts.length ? recentAlerts.map(alert => `
          <button type="button" class="related-item entity-profile-alert" data-entity-alert-id="${escapeHtml(String(alert.id || alert.alert_id || ""))}">
            <span>${escapeHtml(alert.attackType || alert.attack_type || alert.rule || "Alert")}</span>
            <span>${escapeHtml(String(alert.severity || "medium").toUpperCase())}</span>
            <span>${escapeHtml(new Date(alert.timestamp || alert.created_at || Date.now()).toLocaleString())}</span>
          </button>
        `).join("") : '<div class="detail-empty-inline">No recent alerts for this entity.</div>'}
      </div>
    `;
    body.querySelectorAll("[data-entity-alert-id]").forEach(button => {
      button.addEventListener("click", () => {
        modal.hidden = true;
        window.openInvestigation?.(button.getAttribute("data-entity-alert-id"), { forceVisible: true });
      });
    });
    modal.hidden = false;
  }

  window.openEntityProfile = async (entityType, entityKey) => {
    const normalizedType = String(entityType || "").toLowerCase();
    const normalizedKey = String(entityKey || "").trim();
    if (!normalizedType || !normalizedKey) {
      return;
    }
    try {
      const payload = (state.mode === "demo" || !state.apiKey)
        ? buildLocalEntityPayload(normalizedType, normalizedKey)
        : await requestJson(`/entities/${encodeURIComponent(normalizedType)}/${encodeURIComponent(normalizedKey)}`);
      renderEntityProfileModal(payload);
    } catch (error) {
      console.error(error);
      showToast(error.message || "Failed to load entity profile");
    }
  };

  function downloadBlobFile(blob, filename) {
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(href), 1000);
  }

  function downloadJsonFile(filename, payload) {
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    downloadBlobFile(blob, filename);
  }

  async function checkApiHealth() {
    try {
      const payload = await requestJson("/health", { public: true });
      const status = String(payload.status || "unknown").toUpperCase();
      apiHintNode.textContent = payload.database
        ? `API ${status.toLowerCase()} - database ${payload.database}`
        : `API ${status.toLowerCase()}`;
      if (!state.apiKey && state.mode !== "demo") {
        statsPanel.setConnectionStatus({ label: "API READY", tone: "live" });
      }
      return payload;
    } catch (error) {
      statsPanel.setConnectionStatus({ label: "API OFFLINE", tone: "error" });
      apiHintNode.textContent = error.message || "API health check failed";
      throw error;
    }
  }

  function renderDashboardView() {
    statsPanel.render?.();
  }

  function normalizeActivityEntry(entry = {}) {
    const actionEntry = parseActionEntry(entry);
    if (actionEntry) {
      return {
        timestamp: actionEntry.timestamp,
        username: actionEntry.actor || "Unknown",
        action: formatActionLabel(actionEntry),
        targetType: actionEntry.targetType || "system",
        target: actionEntry.targetId || "-",
        details: actionEntry.message || actionEntry.status || "",
        actionObject: actionEntry
      };
    }
    const timestamp = Number(entry.timestamp || entry.created_at || entry.createdAt || Date.now() / 1000);
    const username = entry.username || entry.user || entry.actor || "Unknown";
    const action = String(entry.action || entry.type || "activity").replace(/_/g, " ");
    const targetType = String(entry.targetType || entry.target_type || entry.category || "system").toLowerCase();
    const target = entry.target || entry.target_id || entry.targetId || entry.alert_id || entry.case_id || entry.id || "-";
    const details = entry.details || entry.note || entry.message || "";
    return { timestamp, username, action, targetType, target, details };
  }

  function mergeActivityLogs(...sources) {
    const merged = [];
    const seen = new Set();
    sources.flat().forEach(entry => {
      const normalized = normalizeActivityEntry(entry);
      const key = JSON.stringify([normalized.timestamp, normalized.username, normalized.action, normalized.targetType, normalized.target, normalized.details]);
      if (seen.has(key)) {
        return;
      }
      seen.add(key);
      merged.push(normalized);
    });
    return merged.sort((left, right) => Number(right.timestamp || 0) - Number(left.timestamp || 0));
  }

  function appendActivityLog(action, targetType, target, details = "") {
    dispatchSocAction({
      actionType: action,
      actor: state.user?.username || "Unknown",
      targetType,
      targetId: target,
      relatedCaseId: targetType === "case" ? target : null,
      relatedAlertId: targetType === "alert" ? target : null,
      message: details
    });
  }

  function renderActivityView() {
    if (!activityListNode || !activityStatusNode) {
      return;
    }
    renderOnlineUsersPanel();
    const derivedActivityEntries = selectGlobalActivityStream(state).map(toActivityEntry).filter(Boolean);
    if (derivedActivityEntries.length) {
      activityLogEntries = mergeActivityLogs(activityLogEntries, derivedActivityEntries);
    }
    const usernameFilter = String(activityFilterUserNode?.value || "").trim().toLowerCase();
    const actionFilter = String(activityFilterActionNode?.value || "all").toLowerCase();
    const targetFilter = String(activityFilterTargetNode?.value || "all").toLowerCase();
    const entries = activityLogEntries.filter(entry => {
      const normalizedAction = String(entry.action || entry.actionObject?.actionType || "").toLowerCase();
      const normalizedTargetType = String(entry.targetType || "").toLowerCase();
      if (!isAdmin() && (normalizedTargetType === "auth" || normalizedAction.startsWith("auth_"))) {
        return false;
      }
      if (usernameFilter && !String(entry.username || "").toLowerCase().includes(usernameFilter)) {
        return false;
      }
      if (actionFilter !== "all" && String(entry.action || "").toLowerCase() !== actionFilter) {
        return false;
      }
      if (targetFilter !== "all" && normalizedTargetType !== targetFilter) {
        return false;
      }
      return true;
    });
    const actionOptions = [...new Set(activityLogEntries.map(entry => String(entry.action || "").toLowerCase()).filter(Boolean))].sort();
    if (activityFilterActionNode) {
      const previous = activityFilterActionNode.value || "all";
      activityFilterActionNode.innerHTML = '<option value="all">All actions</option>' + actionOptions.map(action => `<option value="${escapeHtml(action)}">${escapeHtml(action)}</option>`).join("");
      activityFilterActionNode.value = actionOptions.includes(previous) || previous === "all" ? previous : "all";
    }
    activityStatusNode.textContent = entries.length ? `${entries.length} activities` : "No activity loaded";
    activityListNode.innerHTML = entries.length
      ? entries.map(entry => `
        <div class="case-card">
          <div class="case-card-top">
            <strong>${escapeHtml(formatAbsoluteTime(entry.timestamp))}</strong>
            <div class="feed-label-group">
              <span class="record-badge">${escapeHtml(entry.targetType)}</span>
            </div>
          </div>
          <div class="case-card-meta"><span>${escapeHtml(entry.username)}</span><span>${escapeHtml(entry.action)}</span></div>
          <div class="case-card-meta"><span>${escapeHtml(String(entry.target || "-"))}</span><span>${escapeHtml(String(entry.details || ""))}</span></div>
        </div>
      `).join("")
      : '<div class="detail-empty-inline">No activity matches the current filters.</div>';
  }

  function renderInvestigationsView() {
    syncFilteredAlertsState();
    const activeQueue = selectActiveTriageQueue(state);
    const selectedAlert = selectSelectedAlert(state);
    if (selectedAlert && activeQueue.some(alert => String(alert.id || "") === String(selectedAlert.id || ""))) {
      statsPanel.selectAlert?.(state.selectedAlertId, { notifySelection: false });
    } else if (selectedAlert?.id) {
      console.info("PLAYBOOK_RERUN_BLOCKER", {
        alertId: selectedAlert.id,
        reason: "selected_alert_not_in_triage_queue_because_alert_remains_in_case",
        lifecycle: normalizeAlertLifecycle(selectedAlert),
        disposition: selectedAlert.disposition || selectedAlert.alertDisposition || selectedAlert.alert_disposition || "new"
      });
      statsPanel.selectAlert?.(selectedAlert.id, { notifySelection: false });
    } else if (activeQueue.length) {
      const nextState = workflowCommands.selectAlert(state, String(activeQueue[0].id || ""));
      applyWorkflowState(nextState);
      statsPanel.selectAlert?.(state.selectedAlertId, { notifySelection: false });
    } else {
      applyWorkflowState(workflowCommands.selectAlert(state, null));
      statsPanel.render?.();
    }
  }

  function isEditableShortcutTarget(target) {
    const element = target instanceof HTMLElement ? target : null;
    if (!element) {
      return false;
    }
    if (element.closest("[role='dialog'], .modal, .modal-backdrop")) {
      return true;
    }
    const tagName = String(element.tagName || "").toLowerCase();
    if (tagName === "input" || tagName === "textarea" || tagName === "select" || tagName === "button") {
      return true;
    }
    return element.isContentEditable || Boolean(element.closest("[contenteditable='true']"));
  }

  function moveInvestigationsSelection(direction) {
    const filteredAlerts = Array.isArray(statsPanel.getFilteredAlerts?.()) ? statsPanel.getFilteredAlerts() : [];
    if (!filteredAlerts.length) {
      return;
    }
    const currentIndex = filteredAlerts.findIndex(alert => String(alert.id || "") === String(state.selectedAlertId || ""));
    const safeIndex = currentIndex >= 0 ? currentIndex : 0;
    const nextIndex = Math.max(0, Math.min(filteredAlerts.length - 1, safeIndex + direction));
    const nextAlert = filteredAlerts[nextIndex];
    if (!nextAlert) {
      return;
    }
    statsPanel.selectAlert?.(nextAlert.id, { notifySelection: false });
    scrollSelectedInvestigationContext(nextAlert.id);
  }

  async function runInvestigationsShortcut(action) {
    if (investigationShortcutInFlight || Date.now() < investigationShortcutCooldownUntil || state.currentView !== "investigations") {
      return;
    }
    const selectedAlertId = String(state.selectedAlertId || "");
    if (!selectedAlertId) {
      return;
    }
    investigationShortcutInFlight = true;
    try {
      if (action === "create-case") {
        await window.createCaseFromAlert?.(selectedAlertId);
      } else if (action === "false-positive") {
        await window.markFalsePositive?.(selectedAlertId);
      }
      if (state.currentView === "investigations" && state.selectedAlertId) {
        scrollSelectedInvestigationContext(state.selectedAlertId);
      }
    } finally {
      investigationShortcutInFlight = false;
      investigationShortcutCooldownUntil = Date.now() + 150;
    }
  }

  function pulseInvestigationTarget(node) {
    if (!node) {
      return;
    }
    node.classList.remove("search-target-flash");
    void node.offsetWidth;
    node.classList.add("search-target-flash");
    window.setTimeout(() => {
      node.classList.remove("search-target-flash");
    }, 1800);
  }

  function focusInvestigationAlertRow(alertId, { attempts = 8 } = {}) {
    const normalizedAlertId = String(alertId || "");
    if (!normalizedAlertId) {
      showToast("Alert target unavailable");
      return;
    }

    const selectedRow = document.querySelector(`#soc-event-feed [data-alert-id="${CSS.escape(normalizedAlertId)}"]`);
    if (!selectedRow) {
      if (attempts > 0) {
        window.requestAnimationFrame(() => focusInvestigationAlertRow(normalizedAlertId, { attempts: attempts - 1 }));
      } else {
        showToast("Selected alert could not be focused");
      }
      return;
    }

    selectedRow.scrollIntoView({ block: "center", behavior: "smooth" });
    pulseInvestigationTarget(selectedRow);
  }

  function scrollSelectedInvestigationContext(alertId = state.selectedAlertId) {
    window.requestAnimationFrame(() => {
      focusInvestigationAlertRow(alertId);
    });
  }

  function getLinkedAlertsForRecord(record) {
    return [
      ...(Array.isArray(record?.related_alerts) ? record.related_alerts : []),
      ...(Array.isArray(record?.alerts) ? record.alerts : []),
      ...(record?.alert ? [record.alert] : [])
    ].filter(Boolean);
  }

  function recordMatchesEntity(record, entityKey) {
    if (!record || !entityKey) {
      return false;
    }

    return getLinkedAlertsForRecord(record).some(alert => {
      const sourceIp = alert?.source_ip || alert?.sourceIp || alert?.ip || "";
      const userId = alert?.user_id || alert?.userId || "";
      const deviceId = alert?.device_id || alert?.deviceId || "";
      return [sourceIp, userId, deviceId].some(value => String(value || "").toLowerCase() === String(entityKey).toLowerCase());
    });
  }

  function getEntityContext(entityKey) {
    const investigation = state.investigations.find(record => recordMatchesEntity(record, entityKey)) || null;
    const caseRecord = state.cases.find(record => {
      if (recordMatchesEntity(record, entityKey)) {
        return true;
      }
      const linkedInvestigationId = record?.investigation_id;
      return linkedInvestigationId && investigation?.id && String(linkedInvestigationId) === String(investigation.id);
    }) || null;

    return {
      investigation,
      caseRecord
    };
  }

  window.__dashboardGetEntityContext = getEntityContext;

  function buildPriorityBadge(priority) {
    const tone = String(priority || "medium").toLowerCase();
    return `<span class="priority-badge priority-${escapeHtml(tone)}">${escapeHtml(tone.toUpperCase())}</span>`;
  }

  function buildCaseStatusBadge(status) {
    const tone = normalizeCaseStatus(status);
    return `<span class="record-badge status-badge status-${escapeHtml(tone)}">${escapeHtml(CASE_STATUS_LABELS[tone] || tone.toUpperCase())}</span>`;
  }

  function normalizeCaseClosureReason(reason) {
    return String(reason || "").trim().toLowerCase();
  }

  function isFalsePositiveCase(caseRecord) {
    if (!caseRecord || typeof caseRecord !== "object") {
      return false;
    }
    if (normalizeCaseClosureReason(caseRecord.closureReason || caseRecord.closure_reason) === "false_positive") {
      return true;
    }
    const sourceAlert = caseRecord.alert || null;
    if (normalizeAlertLifecycle(sourceAlert || {}) === "false_positive") {
      return true;
    }
    return (Array.isArray(caseRecord.actions) ? caseRecord.actions : []).some(action => {
      const parsed = parseActionEntry(action);
      return String(parsed?.actionType || action?.actionType || action?.type || "").toLowerCase() === "mark_false_positive";
    });
  }

  function renderCaseWorkflowStatus(caseRecordOrStatus) {
    if (caseRecordOrStatus && typeof caseRecordOrStatus === "object") {
      const tone = normalizeCaseStatus(caseRecordOrStatus.status);
      const closureReason = normalizeCaseClosureReason(caseRecordOrStatus.closureReason || caseRecordOrStatus.closure_reason);
      if (tone === "closed" && closureReason === "false_positive") {
        return '<span class="record-badge status-badge status-false_positive">Closed • False Positive</span>';
      }
      if (isFalsePositiveCase(caseRecordOrStatus)) {
        return '<span class="record-badge status-badge status-false_positive">False Positive</span>';
      }
      if (tone === "open" || tone === "closed") {
        return "";
      }
      return buildCaseStatusBadge(tone);
    }
    const tone = normalizeCaseStatus(caseRecordOrStatus);
    if (tone === "open" || tone === "closed") {
      return "";
    }
    return buildCaseStatusBadge(tone);
  }

  function renderSeverityChip(severity) {
    const tone = String(severity || "medium").toLowerCase();
    return `<span class="severity-chip severity-chip-${escapeHtml(tone)}">${escapeHtml(tone.toUpperCase())}</span>`;
  }

  function renderHuntRiskScore(score) {
    const numericScore = Number(score) || 0;
    const tone = numericScore >= 80 ? "high" : (numericScore >= 50 ? "medium" : "low");
    return `<span class="risk-score-pill risk-score-${tone}">${escapeHtml(String(Math.round(numericScore)))}</span>`;
  }

  function formatAbsoluteTime(timestamp) {
    const value = Number(timestamp || 0) * (Number(timestamp || 0) < 9_999_999_999 ? 1000 : 1);
    if (!Number.isFinite(value) || value <= 0) {
      return "Unknown";
    }
    return new Date(value).toLocaleString();
  }

  function getCaseUpdatedTimestamp(caseRecord) {
    return Number(caseRecord?.updated_at || caseRecord?.updatedAt || caseRecord?.created_at || caseRecord?.createdAt || 0);
  }

  function getCaseCreatedTimestamp(caseRecord) {
    return Number(caseRecord?.created_at || caseRecord?.createdAt || caseRecord?.updated_at || caseRecord?.updatedAt || 0);
  }

  function getCurrentActor() {
    return state.user?.username || "Analyst";
  }

  function buildCaseActionNote(actionType, caseRecord, message, input = null, result = null, status = "success") {
    return encodeActionNote(buildActionObject({
      actionType,
      actor: getCurrentActor(),
      targetType: "case",
      targetId: caseRecord?.id || "-",
      relatedCaseId: caseRecord?.id || null,
      relatedAlertId: caseRecord?.source_alert_id || caseRecord?.alert_id || caseRecord?.alert?.id || null,
      input,
      result,
      status,
      message
    }));
  }

  function buildCaseAction(actionType, caseRecord, message, input = null, result = null, status = "success") {
    return buildActionObject({
      actionType,
      actor: getCurrentActor(),
      targetType: "case",
      targetId: caseRecord?.id || "-",
      relatedCaseId: caseRecord?.id || null,
      relatedAlertId: caseRecord?.source_alert_id || caseRecord?.alert_id || caseRecord?.alert?.id || null,
      input,
      result,
      status,
      message
    });
  }

  function parseCaseActivity(note) {
    const actionEntry = parseActionEntry(note);
    if (actionEntry) {
      return {
        type: actionEntry.actionType,
        author: actionEntry.actor || "Unknown",
        label: actionEntry.message || formatActionLabel(actionEntry),
        timestamp: Number(note?.timestamp || 0)
      };
    }
    const text = String(note?.text || note?.message || note || "").trim();
    return {
      type: "note",
      author: "Unknown",
      label: text,
      timestamp: Number(note?.timestamp || 0)
    };
  }

  function buildCaseTimeline(caseRecord) {
    return selectCaseTimeline(caseRecord)
      .filter(entry => entry.label)
      .sort((left, right) => (right.timestamp || 0) - (left.timestamp || 0));
  }

  function getCaseTimeline(caseRecord) {
    return Array.isArray(caseRecord?.timeline) ? caseRecord.timeline : [];
  }

  function appendTimelineToCaseRecord(caseRecord, timelineEvents = []) {
    return appendCaseTimelineEvents(getCaseTimeline(caseRecord), timelineEvents);
  }

  function createCaseTimelineEntry(type, metadata = {}, actor = getCurrentActor(), timestamp = Date.now() / 1000) {
    return buildCaseTimelineEvent({
      type,
      actor,
      timestamp,
      metadata
    });
  }

  function buildCaseCreationTimeline(alert, caseId, actor = getCurrentActor(), timestamp = Date.now() / 1000) {
    return [
      createCaseTimelineEntry("case_created", { caseId, alertId: alert?.id || null }, actor, timestamp),
      createCaseTimelineEntry("case_opened", { status: "open" }, actor, timestamp),
      createCaseTimelineEntry("enrichment_added", {
        source: "source_alert",
        alertId: alert?.id || null,
        attackType: alert?.attackType || alert?.attack_type || null
      }, actor, timestamp)
    ];
  }

  function buildStatusTimelineEvents(caseRecord, nextStatus, actor = getCurrentActor(), timestamp = Date.now() / 1000) {
    const previousStatus = normalizeCaseStatus(caseRecord?.status);
    const normalizedNextStatus = normalizeCaseStatus(nextStatus);
    const events = [];
    if (previousStatus !== normalizedNextStatus) {
      events.push(createCaseTimelineEntry("status_changed", {
        from: previousStatus,
        to: normalizedNextStatus
      }, actor, timestamp));
    }
    if (normalizedNextStatus === "open") {
      events.push(createCaseTimelineEntry("case_opened", { status: normalizedNextStatus }, actor, timestamp));
    }
    if (normalizedNextStatus === "closed") {
      events.push(createCaseTimelineEntry("case_closed", { status: normalizedNextStatus }, actor, timestamp));
    }
    return events;
  }

  function buildFalsePositiveTimelineEvents(caseRecord, closedAt = Date.now()) {
    const timestamp = closedAt / 1000;
    return [
      ...buildStatusTimelineEvents(caseRecord, "closed", getCurrentActor(), timestamp),
      createCaseTimelineEntry("closure_reason_set", { reason: "false_positive" }, getCurrentActor(), timestamp)
    ];
  }

  function normalizeCaseEvidence(caseRecord) {
    const evidence = caseRecord?.evidence && typeof caseRecord.evidence === "object" ? caseRecord.evidence : {};
    return {
      timeline: Array.isArray(evidence.timeline) ? evidence.timeline : [],
      enrichments: Array.isArray(evidence.enrichments) ? evidence.enrichments : [],
      analystNotes: Array.isArray(evidence.analyst_notes) ? evidence.analyst_notes : [],
      artifacts: Array.isArray(evidence.artifacts)
        ? evidence.artifacts
        : (Array.isArray(evidence.bundle) ? evidence.bundle : [])
    };
  }

  function buildEvidenceTimeline(caseRecord) {
    const evidence = normalizeCaseEvidence(caseRecord);
    const entries = evidence.timeline
      .map(parseActionEntry)
      .filter(Boolean)
      .map(entry => ({
        type: entry.actionType || entry.type || "event",
        author: entry.actor || entry.author || "Unknown",
        label: entry.message || formatActionLabel(entry),
        timestamp: Number(entry.timestamp || 0)
      }));
    return entries.sort((left, right) => (right.timestamp || 0) - (left.timestamp || 0));
  }

  function buildAnalystRationaleEntries(caseRecord) {
    return normalizeCaseEvidence(caseRecord).analystNotes
      .map(parseCaseActivity)
      .filter(entry => entry?.label)
      .sort((left, right) => (right.timestamp || 0) - (left.timestamp || 0));
  }

  function renderEvidenceSnapshotSection(caseRecord) {
    const enrichments = normalizeCaseEvidence(caseRecord).enrichments;
    if (!enrichments.length) {
      return '<div class="detail-empty-inline">No enrichment snapshots available.</div>';
    }
    const latest = enrichments[enrichments.length - 1];
    const snapshot = latest?.snapshot && typeof latest.snapshot === "object" ? latest.snapshot : {};
    return `
      <div class="evidence-snapshot-card">
        <div class="timeline-entry-top">
          <span class="timeline-entry-type">Snapshot</span>
          <span class="timeline-time">${escapeHtml(formatAbsoluteTime(latest.timestamp || caseRecord.updated_at || 0))}</span>
        </div>
        <div class="case-context-grid">
          ${renderCaseContextRows([
            { label: "Source", value: latest.source || "source_alert" },
            { label: "Alert ID", value: snapshot.id },
            { label: "Source IP", value: snapshot.source_ip || snapshot.sourceIp || snapshot.ip, iocType: "ip" },
            { label: "Attack type", value: snapshot.attack_type || snapshot.attackType || snapshot.rule },
            { label: "Severity", value: snapshot.severity },
            { label: "Risk score", value: snapshot.risk_score != null ? String(snapshot.risk_score) : "" },
            { label: "Country", value: snapshot.country },
            { label: "Disposition", value: snapshot.disposition },
            { label: "Watchlist", value: snapshot.watchlist_hit ? "Hit" : "" }
          ])}
        </div>
      </div>
    `;
  }

  function renderEvidenceArtifactsSection(caseRecord) {
    const artifacts = normalizeCaseEvidence(caseRecord).artifacts;
    if (!artifacts.length) {
      return '<div class="detail-empty-inline">No evidence recorded for this case yet.</div>';
    }
    return `
      <div class="evidence-artifact-list">
        ${artifacts.map((artifact, index) => {
          const entry = artifact && typeof artifact === "object" ? artifact : { value: artifact };
          const label = entry.label || entry.name || entry.type || `Artifact ${index + 1}`;
          const value = entry.value || entry.id || entry.path || entry.url || entry.description || "";
          const timestamp = entry.timestamp || caseRecord.updated_at || caseRecord.created_at || 0;
          return `
            <div class="timeline-entry evidence-artifact-item">
              <div class="timeline-entry-top">
                <span class="timeline-entry-type">${escapeHtml(String(label))}</span>
                <span class="timeline-time">${escapeHtml(formatAbsoluteTime(timestamp))}</span>
              </div>
              <div class="timeline-text">${escapeHtml(String(value || "Recorded evidence artifact"))}</div>
            </div>
          `;
        }).join("")}
      </div>
    `;
  }

  function buildTimelineEntry(entry) {
    return `<article class="timeline-entry timeline-${escapeHtml(entry.type)}"><div class="timeline-entry-top"><span class="timeline-entry-type">${escapeHtml(entry.type)}</span><span class="timeline-time">${escapeHtml(formatAbsoluteTime(entry.timestamp))}</span></div><div class="timeline-text">${escapeHtml(entry.label)}</div><div class="timeline-author">${escapeHtml(entry.author || "Unknown")}</div></article>`;
  }

  function getCaseLinkedAlerts(caseRecord) {
    const linkedAlerts = [];
    const seen = new Set();
    const addAlert = alert => {
      if (!alert) {
        return;
      }
      const id = String(alert.id || alert.alert_id || buildLocalAlertId(alert) || "");
      if (id && seen.has(id)) {
        return;
      }
      if (id) {
        seen.add(id);
      }
      linkedAlerts.push(alert);
    };

    addAlert(caseRecord?.alert);
    if (Array.isArray(caseRecord?.investigation?.related_alerts)) {
      caseRecord.investigation.related_alerts.forEach(addAlert);
    }

    const linkedIds = Array.isArray(caseRecord?.linked_alert_ids) ? caseRecord.linked_alert_ids : [];
    linkedIds.forEach(alertId => {
      addAlert(findAlertByAnyId(alertId) || statsPanel.getAlertById?.(alertId) || { id: alertId });
    });
    return linkedAlerts;
  }

  function resolveCasePlaybookAlertId(caseRecord) {
    const candidateIds = [
      caseRecord?.source_alert_id,
      caseRecord?.alert_id,
      caseRecord?.sourceAlertId,
      caseRecord?.alert?.id,
      ...(Array.isArray(caseRecord?.linked_alert_ids) ? caseRecord.linked_alert_ids : [])
    ]
      .map(value => String(value || "").trim())
      .filter(Boolean);

    for (const candidateId of candidateIds) {
      const resolvedAlert = findAlertByAnyId(candidateId);
      if (resolvedAlert?.id) {
        return String(resolvedAlert.id);
      }
      if (candidateId) {
        return candidateId;
      }
    }

    const linkedAlert = getCaseLinkedAlerts(caseRecord).find(alert =>
      findAlertByAnyId(alert)?.id
      || String(alert?.id || alert?.alert_id || buildLocalAlertId(alert) || "").trim()
    );
    if (linkedAlert) {
      const resolvedLinkedAlert = findAlertByAnyId(linkedAlert);
      return String(
        resolvedLinkedAlert?.id
        || linkedAlert?.id
        || linkedAlert?.alert_id
        || buildLocalAlertId(linkedAlert)
        || ""
      ).trim();
    }

    const sourceAlertContext = normalizeEnrichmentRecord(caseRecord?.alert || {});
    const sourceIp = String(sourceAlertContext.ip || caseRecord?.source_ip || "").trim();
    const attackType = String(sourceAlertContext.attackType || caseRecord?.attack_type || "").trim().toLowerCase();
    const relatedAlert = (statsPanel.getAlerts?.() || []).find(alert => {
      const normalizedAlert = normalizeEnrichmentRecord(alert);
      const matchesCaseId = String(alert?.caseId || alert?.case_id || alert?.mergedIntoCaseId || "") === String(caseRecord?.id || "");
      const matchesIp = sourceIp && String(normalizedAlert.ip || "").trim() === sourceIp;
      const matchesAttack = attackType && String(normalizedAlert.attackType || "").trim().toLowerCase() === attackType;
      return matchesCaseId || (matchesIp && (!attackType || matchesAttack));
    });
    return String(relatedAlert?.id || "").trim();
  }

  function getRelatedCases(caseRecord) {
    const related = [];
    const seen = new Set();
    const addCase = relatedCase => {
      if (!relatedCase) {
        return;
      }
      const caseId = String(relatedCase.id || "");
      if (!caseId || seen.has(caseId) || caseId === String(caseRecord?.id || "")) {
        return;
      }
      seen.add(caseId);
      related.push(relatedCase);
    };

    const parentCaseId = String(caseRecord?.parent_case_id || caseRecord?.parentCaseId || "");
    if (parentCaseId) {
      addCase(casesCache.find(entry => String(entry.id) === parentCaseId) || { id: parentCaseId, title: `Case ${parentCaseId}`, parent_case_id: null });
    }
    (Array.isArray(caseRecord?.related_cases) ? caseRecord.related_cases : []).forEach(addCase);
    (Array.isArray(caseRecord?.linked_cases) ? caseRecord.linked_cases : []).forEach(caseId => {
      addCase(casesCache.find(entry => String(entry.id) === String(caseId)) || { id: String(caseId), title: `Case ${caseId}` });
    });
    return related;
  }

  function renderCaseRelationshipSection(caseRecord) {
    const parentCaseId = String(caseRecord?.parent_case_id || caseRecord?.parentCaseId || "");
    const relatedCases = getRelatedCases(caseRecord);
    if (!parentCaseId && !relatedCases.length) {
      return '<div class="detail-empty-inline">No linked or parent cases.</div>';
    }
    const parentMarkup = parentCaseId
      ? `<div class="related-list"><button type="button" class="related-item" onclick="window.openCaseRelationship?.('${escapeHtml(parentCaseId)}')"><span>Parent case</span><span>${escapeHtml(parentCaseId)}</span></button></div>`
      : "";
    const relatedMarkup = relatedCases.length
      ? `<div class="related-list">${relatedCases.map(relatedCase => `<button type="button" class="related-item" onclick="window.openCaseRelationship?.('${escapeHtml(relatedCase.id)}')"><span>${escapeHtml(relatedCase.title || relatedCase.id || "Related case")}</span><span>${buildPriorityBadge(relatedCase.priority)} ${renderCaseWorkflowStatus(relatedCase)}</span></button>`).join("")}</div>`
      : "";
    return `${parentMarkup}${relatedMarkup}`;
  }

  function renderCaseContextRows(fields) {
    return fields
      .filter(field => field.value)
      .map(field => `<span><strong>${escapeHtml(field.label)}:</strong> ${field.iocType ? buildIocPivotTriggerMarkup(field.iocType, field.value, { className: "ioc-link" }) : escapeHtml(field.value)}</span>`)
      .join("");
  }

  function filterAndSortCases() {
    const statusFilter = String(caseFilterStatusNode?.value || "all").toLowerCase();
    const priorityFilter = String(caseFilterPriorityNode?.value || "all").toLowerCase();
    const sortBy = String(caseSortNode?.value || "updated_desc").toLowerCase();

    const caseStore = Array.isArray(state.cases) ? state.cases : [];
    const filtered = caseStore.filter(caseRecord => {
      const status = String(caseRecord?.status || "").toLowerCase();
      const normalizedStatus = normalizeCaseStatus(status);
      const priority = String(caseRecord.priority || "medium").toLowerCase();

      if (selectedCaseTab === "active" && !CASE_ACTIVE_STATUSES.includes(normalizedStatus)) {
        return false;
      }
      if (selectedCaseTab === "closed" && normalizedStatus !== "closed") {
        return false;
      }
      if (statusFilter !== "all" && normalizedStatus !== statusFilter) {
        return false;
      }
      if (priorityFilter !== "all" && priority !== priorityFilter) {
        return false;
      }
      return true;
    });

    const priorityRank = { critical: 4, high: 3, medium: 2, low: 1 };
    filtered.sort((left, right) => {
      if (sortBy === "updated_asc") {
        return getCaseUpdatedTimestamp(left) - getCaseUpdatedTimestamp(right);
      }
      if (sortBy === "priority_desc") {
        return (priorityRank[String(right.priority || "medium").toLowerCase()] || 0)
          - (priorityRank[String(left.priority || "medium").toLowerCase()] || 0);
      }
      if (sortBy === "severity_desc") {
        return (priorityRank[String(right.severity || right.alert?.severity || "medium").toLowerCase()] || 0)
          - (priorityRank[String(left.severity || left.alert?.severity || "medium").toLowerCase()] || 0);
      }
      if (sortBy === "status_asc") {
        return String(left.status || "").localeCompare(String(right.status || ""));
      }
      return getCaseUpdatedTimestamp(right) - getCaseUpdatedTimestamp(left);
    });

    return filtered;
  }

  function buildCaseWorkspaceTabButton(tabKey, label) {
    const isActive = selectedCaseWorkspaceTab === tabKey;
    return `<button class="case-workspace-tab${isActive ? " is-active" : ""}" type="button" data-case-detail-tab="${escapeHtml(tabKey)}" aria-pressed="${isActive ? "true" : "false"}">${escapeHtml(label)}</button>`;
  }

  function buildCaseStatusSelect(caseRecord) {
    const currentStatus = normalizeCaseStatus(caseRecord?.status);
    return `
      <select id="case-status-select" onchange="window.submitCaseStatus?.('${escapeHtml(caseRecord.id)}')">
        ${Object.entries(CASE_STATUS_LABELS).map(([value, label]) => `
          <option value="${escapeHtml(value)}"${currentStatus === value ? " selected" : ""}>${escapeHtml(label)}</option>
        `).join("")}
      </select>
    `;
  }

  function renderCasePrimaryActions(caseRecord, options = {}) {
    const {
      canReopen = false,
      showFalsePositiveAction = false,
      sourceAlertLifecycle = "new",
      sourceAlertId = "",
      isExportMenuOpen = false,
      sourceAlert = null,
      canAssign = false,
      isAssigning = false
    } = options;
    const defaultPlaybook = playbookDefinitions[0]?.key || playbookDefinitions[0]?.id || "credential_containment";
    const playbookAlertId = resolveCasePlaybookAlertId(caseRecord);
    const playbookRunState = playbookAlertId
      ? getPlaybookRunState(playbookAlertId, defaultPlaybook, { origin: "cases", caseRecord })
      : { canRun: false, reason: "No linked alert available for this case." };
    const playbookUiState = getCasePlaybookUiState(caseRecord?.id);
    const isPlaybookRunning = playbookUiState.isRunning;
    const playbookButtonDisabled = isPlaybookRunning || !playbookRunState.canRun;
    const playbookReason = playbookUiState.lastError || playbookRunState.reason || "";
    const caseStatusValue = normalizeCaseStatus(caseRecord?.status);
    const showReopenAction = canReopen || caseStatusValue === "closed";
    if (playbookButtonDisabled) {
      console.info("CASE_PLAYBOOK_BUTTON_STATE", {
        caseId: String(caseRecord?.id || ""),
        alertId: playbookAlertId,
        disabledBy: isPlaybookRunning ? "case_ui_running" : "run_state",
        runStateCode: playbookRunState.code || "",
        reason: playbookReason
      });
    }
    return `
      <div class="case-action-bar">
        <div class="case-action-bar-primary">
          ${isAdmin() ? `<button class="button button-secondary" type="button" onclick="window.assignCaseAssignee?.('${escapeHtml(caseRecord.id)}')" ${!canAssign ? "disabled" : ""}>${isAssigning ? "Assigning..." : "Assign"}</button>` : ""}
          <button class="button button-secondary" type="button" onclick="window.runCasePlaybook?.('${escapeHtml(caseRecord.id)}', '${escapeHtml(defaultPlaybook)}')" ${playbookButtonDisabled ? "disabled" : ""}>${isPlaybookRunning ? "Running..." : "Run Playbook"}</button>
          <div class="case-export-menu">
            <button class="button button-secondary" type="button" data-export-menu-toggle="${escapeHtml(caseRecord.id)}" aria-expanded="${isExportMenuOpen ? "true" : "false"}">Export</button>
            ${isExportMenuOpen ? `
              <div class="case-export-dropdown" data-export-menu="${escapeHtml(caseRecord.id)}">
                <button class="button button-secondary button-compact" type="button" data-export-action="full" data-case-id="${escapeHtml(caseRecord.id)}">Full Report</button>
                <button class="button button-secondary button-compact" type="button" data-export-action="timeline" data-case-id="${escapeHtml(caseRecord.id)}">Timeline Only</button>
                <button class="button button-secondary button-compact" type="button" data-export-action="summary" data-case-id="${escapeHtml(caseRecord.id)}">Summary Only</button>
              </div>
            ` : ""}
          </div>
        </div>
        <div class="case-action-bar-secondary">
          ${showFalsePositiveAction
            ? `<button class="button button-secondary" type="button" onclick="window.markCaseAlertFalsePositive?.('${escapeHtml(caseRecord.id)}')" ${sourceAlertLifecycle === "false_positive" ? "disabled" : ""}>Mark False Positive</button>`
            : ""}
        </div>
        <div class="case-action-bar-danger">
          ${showReopenAction
            ? `<button class="button button-secondary" type="button" onclick="window.reopenCase?.('${escapeHtml(caseRecord.id)}')">Reopen Case</button>`
            : `<button class="button button-danger" type="button" onclick="window.updateCaseStatus?.('${escapeHtml(caseRecord.id)}', 'closed')">Close Case</button>`}
        </div>
        ${playbookReason ? `<div class="panel-note">${escapeHtml(playbookReason)}</div>` : ""}
      </div>
    `;
  }

  function getLatestCasePlaybookExecution(caseRecord) {
    return getPlaybookExecutionsForCase(caseRecord)
      .slice()
      .sort((left, right) => Number(right.completed_at || right.started_at || 0) - Number(left.completed_at || left.started_at || 0))[0] || null;
  }

  function renderCaseAutomationBanner(caseRecord, sourceAlertId = "", sourceAlert = null) {
    const latestExecution = getLatestCasePlaybookExecution(caseRecord);
    if (!latestExecution) {
      return `
        <section class="case-automation-banner">
          <div class="case-automation-banner-copy">
            <strong>Automation Results</strong>
            <div class="panel-note">No playbook execution has been run from this case yet.</div>
          </div>
        </section>
      `;
    }
    const blockedIp = (Array.isArray(latestExecution.steps) ? latestExecution.steps : [])
      .map(step => getPlaybookStepResultValue(step, ["ip"]))
      .find(Boolean) || "";
    const isBlockedActive = isIpCurrentlyBlocked(blockedIp);
    return `
      <section class="case-automation-banner">
        <div class="case-automation-banner-copy">
          <strong>Automation Results</strong>
          <div class="panel-note">${escapeHtml(latestExecution.playbook_key || latestExecution.playbook_id || "Playbook")} ran ${escapeHtml(formatAbsoluteTime(latestExecution.completed_at || latestExecution.started_at || 0))}</div>
          ${blockedIp ? `<div class="case-automation-banner-impact">${escapeHtml(isBlockedActive ? `Blocked IP: ${blockedIp}` : `IP unblocked: ${blockedIp}`)}</div>` : ""}
        </div>
        ${blockedIp ? `<div class="case-automation-banner-actions"><button class="button ${isBlockedActive ? "button-success" : "button-secondary"}" type="button" data-playbook-followup="unblock-ip" data-followup-ip="${escapeHtml(blockedIp)}" ${isBlockedActive ? "" : "disabled"}>Unblock IP</button></div>` : ""}
      </section>
    `;
  }

  function renderCaseMoreActions(caseRecord, isReadOnlyCase) {
    const isOpen = openCaseMoreActionsId === String(caseRecord.id);
    if (isReadOnlyCase) {
      return "";
    }
    const blockableIp = getCaseBlockableIp(caseRecord);
    return `
      <div class="case-more-actions">
        <button class="button button-secondary" type="button" data-case-more-actions-toggle="${escapeHtml(caseRecord.id)}" aria-expanded="${isOpen ? "true" : "false"}">More Actions</button>
        ${isOpen ? `
          <div class="case-more-actions-menu" data-case-more-actions-menu="${escapeHtml(caseRecord.id)}">
            <button class="button button-secondary button-compact" type="button" data-case-more-action="block" data-case-id="${escapeHtml(caseRecord.id)}" ${blockableIp ? "" : "disabled"}>Block IP</button>
            <button class="button button-secondary button-compact" type="button" data-case-more-action="merge" data-case-id="${escapeHtml(caseRecord.id)}">Merge Cases</button>
            <button class="button button-secondary button-compact" type="button" data-case-more-action="link" data-case-id="${escapeHtml(caseRecord.id)}">Link Cases</button>
            <button class="button button-secondary button-compact" type="button" data-case-more-action="split" data-case-id="${escapeHtml(caseRecord.id)}">Split Alerts</button>
          </div>
        ` : ""}
      </div>
    `;
  }

  function renderPlaybookExecutionResults(executions = [], caseRecord = null) {
    if (!executions.length) {
      return `
        <section class="detail-section">
          <strong>Automation Results</strong>
          <div class="detail-empty-inline">No playbook executions recorded for this case yet.</div>
        </section>
      `;
    }
    return `
      <section class="detail-section">
        <strong>Automation Results</strong>
        <div class="case-playbook-results">
          ${executions.slice(0, 3).map(execution => {
            const latestCaseId = execution.steps?.map(step => getPlaybookStepResultValue(step, ["caseId", "case_id"])).find(Boolean) || "";
            const blockedIp = execution.steps?.map(step => getPlaybookStepResultValue(step, ["ip"])).find(Boolean) || "";
            const isBlockedActive = isIpCurrentlyBlocked(blockedIp);
            return `
              <article class="case-playbook-result-card">
                <div class="case-playbook-result-header">
                  <div>
                    <strong>${escapeHtml(execution.playbook_key || execution.playbook_id || "Playbook")}</strong>
                    <div class="panel-note">${escapeHtml(execution.automatic ? "Automatic execution" : "Manual execution")} · ${escapeHtml(formatAbsoluteTime(execution.completed_at || execution.started_at || 0))}</div>
                  </div>
                  <span class="case-playbook-status case-playbook-status-${escapeHtml(String(execution.status || "success").toLowerCase())}">${escapeHtml(String(execution.status || "success"))}</span>
                </div>
                <div class="case-playbook-step-list">
                  ${(Array.isArray(execution.steps) ? execution.steps : []).map(step => `
                    <div class="case-playbook-step">
                      <span><strong>${escapeHtml(step.type || "action")}</strong></span>
                      <span>${escapeHtml(step.status || "unknown")}</span>
                      <span>${escapeHtml(
                        getPlaybookStepResultValue(step, ["ip", "assignedTo", "caseId", "case_id"])
                        || (step.result?.suppressed ? "suppressed" : "completed")
                      )}</span>
                    </div>
                  `).join("")}
                </div>
              </article>
            `;
          }).join("")}
        </div>
      </section>
    `;
  }

  function renderBulkCaseActionBar() {
    if (selectedCaseTab !== "active" || !selectedCaseQueue.length) {
      return "";
    }
    return `
      <div class="case-bulk-action-bar">
        <div class="case-bulk-action-copy">
          <strong>${escapeHtml(String(selectedCaseQueue.length))} selected</strong>
          <span class="panel-note">Bulk actions apply to the selected active cases.</span>
        </div>
        <div class="case-bulk-action-buttons">
          ${isAdmin() ? '<button class="button button-secondary" type="button" data-case-bulk-action="assign">Assign Selected</button>' : ""}
          <button class="button button-danger" type="button" data-case-bulk-action="close">Close Selected</button>
          <button class="button button-secondary" type="button" data-case-bulk-action="false-positive">Mark False Positive</button>
          <button class="button button-secondary" type="button" data-case-bulk-action="merge">Merge Selected</button>
          <button class="button button-secondary" type="button" data-case-bulk-action="link">Link Selected</button>
        </div>
      </div>
    `;
  }

  function renderCaseDetails(caseRecord) {
    if (!caseDetailNode) {
      return;
    }
    if (!caseRecord) {
      caseDetailNode.className = "detail-empty";
      caseDetailNode.innerHTML = escapeHtml(caseQueueCompletionMessage || "Select a case to inspect incident context and update workflow.");
      return;
    }

    caseQueueCompletionMessage = "";

    const sourceAlert = caseRecord.alert || null;
    const sourceAlertId = caseRecord.source_alert_id || caseRecord.alert_id || sourceAlert?.id || "";
    const linkedAlertFrontendId = getFrontendAlertId(sourceAlertId);
    const linkedInvestigationId = caseRecord.source_investigation_id || caseRecord.investigation_id || caseRecord.investigation?.id || "";
    const linkedAlerts = getCaseLinkedAlerts(caseRecord);
    const timelineEntries = buildCaseTimeline(caseRecord);
    const evidenceTimelineEntries = buildEvidenceTimeline(caseRecord);
    const analystRationaleEntries = buildAnalystRationaleEntries(caseRecord);
    const caseStatusValue = normalizeCaseStatus(caseRecord.status);
    const canReopen = caseStatusValue === "closed";
    const isReadOnlyCase = false;
    const sourceAlertContext = normalizeEnrichmentRecord(sourceAlert || linkedAlerts[0] || {});
    const queuePosition = selectedCaseTab === "active" ? getQueuePosition(selectedCaseQueue, caseRecord.id) : null;
    const sourceAlertLifecycle = normalizeAlertLifecycle(sourceAlert || {});
    const showFalsePositiveAction = !isReadOnlyCase && sourceAlertId;
    const activeWorkspaceTab = normalizeCaseWorkspaceTab(selectedCaseWorkspaceTab);
    const canAdminAssignCase = isAdmin() && !isReadOnlyCase;
    const assigneeOptions = [...new Set([
      ...getSessionAssignableUsers(),
      ...availableCaseAssignees,
      caseRecord.assignee,
    ].filter(username => typeof username === "string" && String(username).trim()))]
      .sort((left, right) => String(left).localeCompare(String(right)));
    const isSavingAssignee = pendingCaseAssigneeId === String(caseRecord.id);
    const savedAssignee = String(caseRecord.assignee || "").trim();
    const pendingAssigneeSelection = Object.prototype.hasOwnProperty.call(pendingCaseAssigneeSelections, String(caseRecord.id))
      ? String(pendingCaseAssigneeSelections[String(caseRecord.id)] || "").trim()
      : savedAssignee;
    const hasPendingAssigneeChange = pendingAssigneeSelection !== savedAssignee;
    const isExportMenuOpen = openExportMenuCaseId === String(caseRecord.id);
    const playbookExecutionsForCase = getPlaybookExecutionsForCase(caseRecord);

    const tabContentMap = {
      overview: `
        <div class="case-workspace-grid">
          <section class="detail-section">
            <strong>Overview</strong>
            <div class="case-context-grid">
              <span><strong>Summary</strong> ${escapeHtml(caseRecord.summary || "No case summary recorded.")}</span>
              <span><strong>Linked alert</strong> ${escapeHtml(sourceAlertId || "None")}</span>
              <span><strong>Linked investigation</strong> ${escapeHtml(linkedInvestigationId || "None")}</span>
              <span><strong>Status</strong> ${escapeHtml(CASE_STATUS_LABELS[caseStatusValue] || caseStatusValue)}</span>
              <span><strong>Assignee</strong> ${escapeHtml(caseRecord.assignee || "Unassigned")}</span>
              <span><strong>Priority</strong> ${escapeHtml(String(caseRecord.priority || "medium").toUpperCase())}</span>
              <span><strong>Severity</strong> ${escapeHtml(String(caseRecord.severity || sourceAlert?.severity || "medium").toUpperCase())}</span>
            </div>
          </section>
          <section class="detail-section">
            <strong>Case Relationships</strong>
            ${renderCaseRelationshipSection(caseRecord)}
          </section>
        </div>
        <section class="detail-section">
          <strong>Source Context</strong>
          <div class="case-context-grid">
            ${renderCaseContextRows([
              { label: "Source IP", value: sourceAlertContext.ip, iocType: "ip" },
              { label: "Destination IP", value: sourceAlertContext.destinationIp, iocType: "ip" },
              { label: "Attack type", value: sourceAlertContext.attackType },
              { label: "Country", value: sourceAlertContext.country },
              { label: "Region", value: sourceAlertContext.region },
              { label: "City", value: sourceAlertContext.city },
              { label: "ASN", value: sourceAlertContext.asn },
              { label: "Provider", value: sourceAlertContext.isp },
              { label: "Reputation", value: getIpReputation(sourceAlert || linkedAlerts[0] || {}) },
              { label: "Username", value: sourceAlertContext.username, iocType: "username" },
              { label: "Account", value: sourceAlertContext.account, iocType: "username" },
              { label: "Email", value: sourceAlertContext.email || sourceAlertContext.userEmail, iocType: "email" },
              { label: "Email Domain", value: sourceAlertContext.domain, iocType: "domain" },
              { label: "Device", value: sourceAlertContext.device },
              { label: "Hostname", value: sourceAlertContext.hostname, iocType: "hostname" },
              { label: "OS", value: sourceAlertContext.deviceOs },
              { label: "Browser", value: sourceAlertContext.browser },
              { label: "Threat level", value: sourceAlertContext.threatLevel },
              { label: "Related entity", value: sourceAlertContext.relatedEntity }
            ])}
          </div>
          ${sourceAlertId
            ? `<div class="related-list"><button type="button" class="related-item" onclick="window.openInvestigation?.('${escapeHtml(linkedAlertFrontendId)}')"><span>${escapeHtml(sourceAlertContext.attackType || "Linked alert")}</span><span>${escapeHtml(sourceAlertContext.ip || sourceAlertId || "unknown")}</span></button></div>`
            : '<div class="detail-empty-inline">No linked source alert available.</div>'
          }
        </section>
        ${renderPlaybookExecutionResults(playbookExecutionsForCase, caseRecord)}
      `,
      evidence: `
        <section class="detail-section evidence-panel evidence-panel-header">
          <strong>Evidence</strong>
          <div class="panel-note">Enrichment snapshots, artifacts, and automation outputs linked to this case.</div>
        </section>
        <section class="detail-section evidence-panel">
          <strong>Evidence Timeline</strong>
          ${evidenceTimelineEntries.length
            ? `<div class="case-timeline">${evidenceTimelineEntries.map(buildTimelineEntry).join("")}</div>`
            : '<div class="detail-empty-inline">No evidence recorded for this case yet.</div>'
          }
        </section>
        <section class="detail-section evidence-panel">
          <strong>Enrichment Snapshot</strong>
          ${renderEvidenceSnapshotSection(caseRecord)}
        </section>
        <section class="detail-section evidence-panel">
          <strong>Evidence Bundle / Related Artifacts</strong>
          ${renderEvidenceArtifactsSection(caseRecord)}
        </section>
      `,
      timeline: `
        <section class="detail-section case-notes-section">
          <strong>Timeline</strong>
          ${timelineEntries.length
            ? `<div class="case-timeline">${timelineEntries.map(buildTimelineEntry).join("")}</div>`
            : '<div class="detail-empty-inline">No case activity yet.</div>'
          }
        </section>
      `,
      related_alerts: `
        <section class="detail-section">
          <strong>Alerts</strong>
          ${linkedAlerts.length
            ? `<div class="related-list">${linkedAlerts.map(alert => {
              const alertId = String(alert.id || alert.alert_id || "");
              const frontendId = getFrontendAlertId(alertId);
              const severity = String(alert.severity || "medium").toLowerCase();
              const context = normalizeEnrichmentRecord(alert);
              return `<button type="button" class="related-item related-alert-row" onclick="window.openInvestigation?.('${escapeHtml(frontendId)}')"><span>${renderSeverityChip(severity)} ${escapeHtml(context.attackType || alertId || "Linked alert")}</span><span>${escapeHtml(context.ip || "unknown")}</span><span>${escapeHtml(context.location || context.country || "Unknown")} · ${escapeHtml(getIpReputation(alert))}</span><span>${escapeHtml(context.device || context.hostname || context.email || context.domain || "No device/email")}</span><span>${escapeHtml(formatAbsoluteTime(alert.timestamp || alert.created_at || alert.createdAt || 0))}</span></button>`;
            }).join("")}</div>`
            : '<div class="detail-empty-inline">No linked alerts available.</div>'
          }
        </section>
      `,
      notes: `
        <section class="detail-section case-notes-section">
          <strong>Notes</strong>
          <label class="field case-notes-input">
            <textarea id="case-note-input" rows="6" placeholder="Add investigation notes, findings, actions..." ${isReadOnlyCase ? "disabled" : ""}></textarea>
          </label>
          ${isReadOnlyCase ? "" : `<div class="case-notes-actions">
            <button class="button button-primary" type="button" onclick="window.addCaseNote?.('${escapeHtml(caseRecord.id)}')">Add Note</button>
          </div>`}
          ${analystRationaleEntries.length
            ? `<div class="case-timeline">${analystRationaleEntries.map(buildTimelineEntry).join("")}</div>`
            : '<div class="detail-empty-inline">No analyst notes yet.</div>'
          }
        </section>
      `
    };

    caseDetailNode.className = "detail-panel";
    caseDetailNode.innerHTML = `
      <section class="case-workspace-shell">
        <div class="case-workspace-header">
          <div class="case-header-copy">
            <h3>${escapeHtml(caseRecord.title || "Untitled case")}</h3>
            <div class="case-header-meta">
              <button
                class="case-id-token"
                type="button"
                data-copy-case-id="${escapeHtml(caseRecord.id)}"
                title="Click to copy Case ID"
                aria-label="Copy case ID ${escapeHtml(caseRecord.id)}"
              >
                <span class="case-id-token-label">Case ID</span>
                <span class="case-id-token-value">${escapeHtml(caseRecord.id)}</span>
                <span class="case-id-token-icon" aria-hidden="true">
                  <svg viewBox="0 0 16 16" focusable="false">
                    <path d="M5 2h6a2 2 0 0 1 2 2v7h-2V4H5V2Zm-2 3h6a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2Zm0 2v7h6V7H3Z"></path>
                  </svg>
                </span>
              </button>
              <button
                class="button button-secondary button-compact case-link-copy-button"
                type="button"
                data-copy-case-link="${escapeHtml(caseRecord.id)}"
                aria-label="Copy shareable case link"
                title="Copy shareable case link"
              >
                <svg viewBox="0 0 16 16" focusable="false" aria-hidden="true">
                  <path d="M6.2 4.8 4.4 6.6a2 2 0 0 0 2.8 2.8l1-1 1.4 1.4-1 1a4 4 0 1 1-5.6-5.6l1.8-1.8 1.4 1.4Zm5.6 0a4 4 0 0 1 0 5.6L10 12.2l-1.4-1.4 1.8-1.8a2 2 0 0 0-2.8-2.8l-1 1-1.4-1.4 1-1a4 4 0 0 1 5.6 0Z"></path>
                </svg>
              </button>
              ${renderSeverityChip(String(caseRecord.severity || sourceAlert?.severity || "medium").toLowerCase())}
              ${renderCaseWorkflowStatus(caseRecord)}
              ${buildPriorityBadge(caseRecord.priority)}
              <span><strong>Assignee</strong> ${escapeHtml(caseRecord.assignee || "Unassigned")}</span>
              <span><strong>Created</strong> ${escapeHtml(formatAbsoluteTime(caseRecord.created_at))}</span>
              <span><strong>Updated</strong> ${escapeHtml(formatAbsoluteTime(caseRecord.updated_at))}</span>
            </div>
          </div>
          <div class="case-header-controls">
            <label class="field">
              <span>Status</span>
              ${buildCaseStatusSelect(caseRecord)}
            </label>
            <label class="field">
              <span>Priority</span>
              <select id="case-priority-select" onchange="window.submitCasePriority?.('${escapeHtml(caseRecord.id)}')">
                <option value="critical"${String(caseRecord.priority || "").toLowerCase() === "critical" ? " selected" : ""}>Critical</option>
                <option value="high"${String(caseRecord.priority || "").toLowerCase() === "high" ? " selected" : ""}>High</option>
                <option value="medium"${String(caseRecord.priority || "").toLowerCase() === "medium" ? " selected" : ""}>Medium</option>
                <option value="low"${String(caseRecord.priority || "").toLowerCase() === "low" ? " selected" : ""}>Low</option>
              </select>
            </label>
            <label class="field">
              <span>Assignee</span>
              ${canAdminAssignCase ? `
                <select id="case-assignee-input" ${isSavingAssignee ? "disabled" : ""} onchange="window.handleCaseAssigneeSelectionChange?.('${escapeHtml(caseRecord.id)}')">
                  <option value="">Unassigned</option>
                  ${assigneeOptions.map(username => `<option value="${escapeHtml(username)}"${pendingAssigneeSelection === String(username) ? " selected" : ""}>${escapeHtml(username)}</option>`).join("")}
                </select>
              ` : `
                <input id="case-assignee-input" type="text" value="${escapeHtml(caseRecord.assignee || "Unassigned")}" readonly disabled>
              `}
            </label>
          </div>
          ${canAdminAssignCase && (isSavingAssignee || hasPendingAssigneeChange) ? `
            <div class="case-header-assignee-actions">
              <span class="case-header-helper panel-note">${isSavingAssignee ? "Saving assignment..." : "Select Assign to apply the updated owner."}</span>
            </div>
          ` : ""}
        </div>

        <div class="case-workspace-toolbar">
          ${renderCasePrimaryActions(caseRecord, {
            canReopen,
            isReadOnlyCase,
            showFalsePositiveAction,
            sourceAlertLifecycle,
            sourceAlertId,
            isExportMenuOpen,
            sourceAlert,
            canAssign: hasPendingAssigneeChange,
            isAssigning: isSavingAssignee
          })}
          ${renderCaseMoreActions(caseRecord, isReadOnlyCase)}
        </div>

        ${renderCaseAutomationBanner(caseRecord, sourceAlertId, sourceAlert)}

        <div class="case-detail-tabs">
          ${buildCaseWorkspaceTabButton("overview", "Overview")}
          ${buildCaseWorkspaceTabButton("evidence", "Evidence")}
          ${buildCaseWorkspaceTabButton("timeline", "Timeline")}
          ${buildCaseWorkspaceTabButton("related_alerts", "Alerts")}
          ${buildCaseWorkspaceTabButton("notes", "Notes")}
        </div>

        <div class="case-workspace-tab-panel">
          ${tabContentMap[activeWorkspaceTab] || tabContentMap.overview}
        </div>
      </section>
    `;

    caseDetailNode.querySelectorAll("[data-case-detail-tab]").forEach(button => {
      button.addEventListener("click", () => {
        setCaseWorkspaceTab(button.getAttribute("data-case-detail-tab"));
      });
    });
    caseDetailNode.querySelectorAll("[data-copy-case-id]").forEach(button => {
      button.addEventListener("click", async event => {
        event.preventDefault();
        await copyTextToClipboard(
          button.getAttribute("data-copy-case-id") || "",
          "Case ID copied",
          "Copy failed"
        );
      });
    });
    caseDetailNode.querySelectorAll("[data-copy-case-link]").forEach(button => {
      button.addEventListener("click", async event => {
        event.preventDefault();
        const caseId = button.getAttribute("data-copy-case-link") || "";
        await copyTextToClipboard(
          buildCaseDeepLinkUrl(caseId),
          "Case link copied",
          "Copy failed"
        );
      });
    });
    caseDetailNode.querySelectorAll("[data-export-menu-toggle]").forEach(button => {
      button.addEventListener("click", event => {
        event.stopPropagation();
        const caseId = String(button.getAttribute("data-export-menu-toggle") || "");
        openExportMenuCaseId = openExportMenuCaseId === caseId ? null : caseId;
        renderCasesView();
      });
    });
    caseDetailNode.querySelectorAll("[data-export-action]").forEach(button => {
      button.addEventListener("click", async event => {
        event.stopPropagation();
        const caseId = String(button.getAttribute("data-case-id") || "");
        const action = String(button.getAttribute("data-export-action") || "");
        openExportMenuCaseId = null;
        renderCasesView();
        if (action === "timeline") {
          await window.exportCaseTimeline?.(caseId);
          return;
        }
        if (action === "summary") {
          await window.exportCaseSummary?.(caseId);
          return;
        }
        await window.exportCaseReport?.(caseId);
      });
    });
    caseDetailNode.querySelectorAll("[data-case-more-actions-toggle]").forEach(button => {
      button.addEventListener("click", event => {
        event.stopPropagation();
        const caseId = String(button.getAttribute("data-case-more-actions-toggle") || "");
        openCaseMoreActionsId = openCaseMoreActionsId === caseId ? null : caseId;
        renderCasesView();
      });
    });
    caseDetailNode.querySelectorAll("[data-case-more-action]").forEach(button => {
      button.addEventListener("click", async event => {
        event.stopPropagation();
        const caseId = String(button.getAttribute("data-case-id") || "");
        const action = String(button.getAttribute("data-case-more-action") || "");
        openCaseMoreActionsId = null;
        renderCasesView();
        if (action === "block") {
          await window.blockCaseIp?.(caseId);
          return;
        }
        if (action === "merge") {
          await window.mergeCases?.(caseId);
          return;
        }
        if (action === "link") {
          await window.linkCases?.(caseId);
          return;
        }
        await window.splitCaseAlerts?.(caseId);
      });
    });
    caseDetailNode.querySelectorAll("[data-playbook-followup]").forEach(button => {
      button.addEventListener("click", async event => {
        event.stopPropagation();
        const action = button.getAttribute("data-playbook-followup");
        if (action === "unblock-ip") {
          await window.unblockIp?.(button.getAttribute("data-followup-ip"));
          return;
        }
        if (action === "rerun-playbook") {
          await window.runAlertPlaybook?.(
            button.getAttribute("data-followup-alert-id"),
            button.getAttribute("data-followup-playbook"),
            { caseId: caseRecord.id, source: "cases" }
          );
          return;
        }
        if (action === "remove-watchlist") {
          await window.removeFromWatchlist?.(
            button.getAttribute("data-followup-type"),
            button.getAttribute("data-followup-value")
          );
          return;
        }
        if (action === "reopen-case") {
          await window.updateCaseStatus?.(button.getAttribute("data-followup-case-id"), "open");
        }
      });
    });
  }

  function renderCasesView() {
    const caseListNodes = [casesListNode].filter(Boolean);
    const caseStatusNodes = [casesStatusNode].filter(Boolean);

    if (!caseListNodes.length || !caseStatusNodes.length) {
      return;
    }

    const filteredCases = filterAndSortCases();
    syncSelectedCaseQueue();
    caseTabActiveNode?.classList.toggle("is-active", selectedCaseTab === "active");
    caseTabClosedNode?.classList.toggle("is-active", selectedCaseTab === "closed");
    caseStatusNodes.forEach(node => {
      node.textContent = filteredCases.length
        ? `${filteredCases.length} of ${casesCache.length} cases`
        : (casesCache.length ? "No cases match filters" : "No cases loaded");
    });
    if (!filteredCases.length) {
      openCaseMoreActionsId = null;
      caseListNodes.forEach(node => {
        node.innerHTML = `<div class="detail-empty-inline">${casesCache.length ? "No cases match the current filters." : "No active cases yet."}</div>`;
      });
      setCurrentCaseSelection(null, { suppressAutoSelect: false });
      renderCaseDetails(null);
      return;
    }

    let currentCase = filteredCases.find(entry => String(entry.id) === String(selectedCaseId)) || selectCurrentQueueCase(state) || null;
    if (!currentCase && pendingQueuedCaseId) {
      currentCase = filteredCases.find(entry => String(entry.id) === String(pendingQueuedCaseId)) || null;
    }
    if (!currentCase && selectedCaseTab === "active" && selectedCaseQueue.length) {
      const queuedVisibleId = getQueueVisibleCaseId(selectedCaseQueue, filteredCases);
      currentCase = filteredCases.find(entry => String(entry.id) === String(queuedVisibleId)) || null;
    }
    if (!currentCase && suppressCaseAutoSelect) {
      suppressCaseAutoSelect = false;
      setCurrentCaseSelection(null, { suppressAutoSelect: false });
    } else if (!currentCase) {
      currentCase = filteredCases[0];
      setCurrentCaseSelection(currentCase?.id || null, { suppressAutoSelect: false });
    } else {
      setCurrentCaseSelection(currentCase.id, { suppressAutoSelect: false, preserveWorkspaceTab: true });
    }
    pendingQueuedCaseId = currentCase?.id ? String(currentCase.id) : null;

    const casesMarkup = `
      ${renderBulkCaseActionBar()}
      ${filteredCases.map(caseRecord => `
      <div
        class="case-card${String(caseRecord.id) === String(selectedCaseId) ? " is-selected" : ""}${selectedCaseTab === "active" && selectedCaseQueue.includes(String(caseRecord.id)) ? " is-queued" : ""}"
        data-case-id="${escapeHtml(caseRecord.id)}"
        role="button"
        tabindex="0"
      >
        <div class="case-card-top">
          <div class="case-card-title-row">
            ${selectedCaseTab === "active" ? `
              <label class="case-row-select" aria-label="Select case ${escapeHtml(caseRecord.title || "Untitled case")}">
                <input
                  type="checkbox"
                  data-case-queue-id="${escapeHtml(caseRecord.id)}"
                  ${selectedCaseQueue.includes(String(caseRecord.id)) ? "checked" : ""}
                >
              </label>
            ` : ""}
            <div class="case-copy">
              <strong>${escapeHtml(caseRecord.title || "Untitled case")}</strong>
              <span class="case-card-age">${escapeHtml(formatRelativeTime(caseRecord.updated_at || caseRecord.updatedAt || caseRecord.created_at))}</span>
            </div>
          </div>
          <div class="feed-label-group">
            ${renderSeverityChip(String(caseRecord.severity || caseRecord.priority || "medium").toLowerCase())}
            ${renderCaseWorkflowStatus(caseRecord)}
          </div>
        </div>
        <div class="case-card-meta">
          <span>${escapeHtml(caseRecord.assignee || "Unassigned")}</span>
          ${buildPriorityBadge(caseRecord.priority)}
        </div>
      </div>
    `).join("")}
    `;
    caseListNodes.forEach(node => {
      node.innerHTML = casesMarkup;
      node.querySelectorAll("[data-case-bulk-action]").forEach(button => {
        button.addEventListener("click", async event => {
          event.stopPropagation();
          await window.runCaseBulkAction?.(button.getAttribute("data-case-bulk-action"));
        });
      });
      node.querySelectorAll("[data-case-id]").forEach(button => {
        const openCase = () => {
          setCurrentCaseSelection(button.getAttribute("data-case-id"));
          renderCasesView();
        };
        button.addEventListener("click", openCase);
        button.addEventListener("keydown", event => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            openCase();
          }
        });
      });
      node.querySelectorAll("[data-case-queue-id]").forEach(input => {
        input.closest(".case-row-select")?.addEventListener("click", event => {
          event.stopPropagation();
        });
        input.addEventListener("click", event => {
          event.stopPropagation();
        });
        input.addEventListener("change", event => {
          event.stopPropagation();
          toggleQueuedCase(input.getAttribute("data-case-queue-id"), event.target.checked);
          renderCasesView();
        });
      });
    });
    renderCaseDetails(currentCase);
  }

  async function loadInvestigations() {
    if (state.mode === "demo" || !state.apiKey) {
      setInvestigationsState([]);
      return;
    }
    const payload = await requestJson("/investigations");
    setInvestigationsState(Array.isArray(payload.investigations) ? payload.investigations : []);
  }

  async function loadWatchlist() {
    if (state.mode === "demo" || !state.apiKey) {
      state.watchlist = [];
      return;
    }
    const payload = await requestJson("/watchlist");
    state.watchlist = Array.isArray(payload.entries) ? payload.entries : [];
  }

  async function loadPlaybooks() {
    if (state.mode === "demo" || !state.apiKey) {
      playbookDefinitions = [
        {
          key: "credential_containment",
          id: "playbook-credential-containment",
          title: "Credential Containment",
          summary: "Enrich hostile IP context, create a case, assign an analyst, and block the IP.",
          actions: [{ type: "enrich_ip" }, { type: "check_threat_intel" }, { type: "create_case" }, { type: "assign_analyst" }, { type: "block_ip" }],
        },
      ];
      playbookExecutions = [];
      renderAdminSocView();
      return;
    }
    const payload = await requestJson("/playbooks");
    playbookDefinitions = Array.isArray(payload.playbooks) ? payload.playbooks : [];
    playbookExecutions = Array.isArray(payload.executions) ? payload.executions : [];
    renderAdminSocView();
  }

  async function loadCases() {
    if (state.mode === "demo" || !state.apiKey) {
      setCasesState(loadStoredDemoCases());
      selectedCaseQueue = [];
      suppressCaseAutoSelect = false;
      pendingQueuedCaseId = null;
      syncCaseQueueState();
      renderCasesView();
      return;
    }
    const payload = await requestJson("/cases");
    setCasesState(Array.isArray(payload.cases)
      ? payload.cases.map(entry => ({ ...entry, status: normalizeCaseStatus(entry.status) }))
      : []);
    await loadAssignableUsers();
    syncSelectedCaseQueue();
    syncCaseQueueState();
    renderCasesView();
  }

  function getFallbackAssignableUsers() {
    return [...new Set([
      state.user?.username,
      currentUser?.username,
      ...casesCache.map(entry => entry.assignee).filter(Boolean),
    ].filter(Boolean))].sort((left, right) => String(left).localeCompare(String(right)));
  }

  function getSessionAssignableUsers() {
    const sessionUsers = state.user?.assignableUsers?.length
      ? state.user.assignableUsers
      : (state.user?.assignable_users?.length ? state.user.assignable_users : getStoredAssignableUsers());
    return [...new Set(
      (Array.isArray(sessionUsers) ? sessionUsers : [])
        .map(entry => typeof entry === "string" ? entry : entry?.username)
        .map(value => String(value || "").trim())
        .filter(Boolean)
    )].sort((left, right) => String(left).localeCompare(String(right)));
  }

  async function loadAssignableUsers() {
    if (!isAuthenticated() || !isAdmin()) {
      availableCaseAssignees = [];
      if (state.currentView === "cases") {
        renderCasesView();
      }
      return;
    }
    const sessionAssignableUsers = getSessionAssignableUsers();
    if (sessionAssignableUsers.length) {
      availableCaseAssignees = sessionAssignableUsers;
    }
    if (state.mode === "demo" || !state.apiKey) {
      availableCaseAssignees = sessionAssignableUsers.length ? sessionAssignableUsers : getFallbackAssignableUsers();
      return;
    }
    try {
      const payload = await requestJson("/users");
      const fetchedUsers = Array.isArray(payload.users)
        ? [...new Set(payload.users
          .map(entry => ({
            username: String(entry?.username || "").trim(),
            role: String(entry?.role || "analyst").toLowerCase()
          }))
          .filter(entry => entry.username && entry.role !== "system")
          .map(entry => entry.username))]
        : [];
      availableCaseAssignees = fetchedUsers.length ? fetchedUsers : (sessionAssignableUsers.length ? sessionAssignableUsers : getFallbackAssignableUsers());
    } catch (error) {
      console.error(error);
      availableCaseAssignees = sessionAssignableUsers.length ? sessionAssignableUsers : getFallbackAssignableUsers();
    }
    if (state.currentView === "cases") {
      renderCasesView();
    }
  }

  function getSearchTokens(query) {
    return String(query || "").trim().toLowerCase().split(/\s+/).filter(Boolean);
  }

  function getAlertSearchFields(alert) {
    return [
      alert?.attackType,
      alert?.attack_type,
      alert?.rule,
      alert?.sourceIp,
      alert?.source_ip,
      alert?.ip,
      alert?.userId,
      alert?.user_id,
      alert?.country,
      alert?.severity,
      alert?.status
    ].map(value => String(value || "").trim().toLowerCase()).filter(Boolean);
  }

  function getAlertSearchKey(alert) {
    return String(
      alert?.id ||
      alert?.alert_id ||
      buildLocalAlertId(alert) ||
      [
        alert?.attackType || alert?.attack_type || alert?.rule || "",
        alert?.sourceIp || alert?.source_ip || alert?.ip || "",
        alert?.country || "",
        alert?.timestamp || alert?.created_at || alert?.createdAt || ""
      ].join("|")
    );
  }

  function matchesAlertSearchQuery(alert, query) {
    const queryTokens = Array.isArray(query) ? query : getSearchTokens(query);
    if (!queryTokens.length) {
      return false;
    }
    if (queryTokens.length === 1 && /^[a-z]{2}$/.test(queryTokens[0])) {
      return String(alert?.country || "").trim().toLowerCase() === queryTokens[0];
    }
    const fields = getAlertSearchFields(alert);
    return queryTokens.every(token => fields.some(field => field.includes(token)));
  }

  function filterAlertsForSearch(alerts, query) {
    const queryTokens = getSearchTokens(query);
    const seen = new Set();
    return (Array.isArray(alerts) ? alerts : []).filter(alert => {
      if (!matchesAlertSearchQuery(alert, queryTokens)) {
        return false;
      }
      const key = getAlertSearchKey(alert);
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }

  function getSeveritySortWeight(severity) {
    const order = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1
    };
    return order[String(severity || "medium").toLowerCase()] || 0;
  }

  function sortHuntResults(alerts, sortBy = currentHuntSort) {
    const items = [...(Array.isArray(alerts) ? alerts : [])];
    items.sort((left, right) => {
      switch (sortBy) {
        case "risk_desc":
          return (Number(right.riskScore ?? right.risk_score ?? 0) || 0) - (Number(left.riskScore ?? left.risk_score ?? 0) || 0);
        case "severity_desc":
          return getSeveritySortWeight(right.severity) - getSeveritySortWeight(left.severity);
        case "attack_asc":
          return String(left.attackType || left.attack_type || left.rule || "").localeCompare(String(right.attackType || right.attack_type || right.rule || ""));
        case "ip_asc":
          return String(left.sourceIp || left.source_ip || left.ip || "").localeCompare(String(right.sourceIp || right.source_ip || right.ip || ""));
        case "time_desc":
        default:
          return Number(right.timestamp || 0) - Number(left.timestamp || 0);
      }
    });
    return items;
  }

  function getHuntFilterState() {
    return {
      caseStatus: String(currentHuntCaseStatusFilter || "all").toLowerCase(),
      attackType: String(currentHuntAttackFilter || "").trim().toLowerCase(),
      alertStatus: String(currentHuntAlertStatusFilter || "all").toLowerCase(),
      username: String(currentHuntUserFilter || "").trim().toLowerCase(),
      minRisk: Number(currentHuntMinRiskFilter)
    };
  }

  function resolveHuntLinkedCase(alert) {
    const directCaseId = String(alert?.caseId || alert?.case_id || "").trim();
    if (directCaseId) {
      const directCase = casesCache.find(entry => String(entry.id || "") === directCaseId) || null;
      if (directCase) {
        return directCase;
      }
    }
    const linkedCase = selectLinkedCaseForAlert(state, String(alert?.id || "")) || null;
    if (linkedCase?.id) {
      return linkedCase;
    }
    return casesCache.find(entry =>
      String(entry.id || "") === String(alert?.mergedIntoCaseId || alert?.merged_into_case_id || "")
      || String(entry.source_alert_id || entry.alert_id || entry.sourceAlertId || "") === String(alert?.id || "")
    ) || null;
  }

  function buildHuntCaseMeta(alert) {
    const linkedCase = resolveHuntLinkedCase(alert);
    if (!linkedCase?.id) {
      return {
        caseId: "",
        caseLabel: "No case",
        caseBucket: "no_case",
        caseStatus: ""
      };
    }
    const normalizedStatus = normalizeCaseStatus(linkedCase.status);
    const caseBucket = normalizedStatus === "closed" ? "closed_case" : "active_case";
    return {
      caseId: String(linkedCase.id || ""),
      caseLabel: normalizedStatus === "closed" ? "Closed case" : "Active case",
      caseBucket,
      caseStatus: normalizedStatus
    };
  }

  function matchesHuntViewFilters(alert) {
    const filters = getHuntFilterState();
    const attackType = String(alert.attackType || "").toLowerCase();
    const alertStatus = String(alert.status || "").toLowerCase();
    const username = String(alert.userId || "").toLowerCase();
    const riskScore = Number(alert.riskScore || 0) || 0;
    if (filters.caseStatus !== "all" && alert.caseBucket !== filters.caseStatus) {
      return false;
    }
    if (filters.attackType && !attackType.includes(filters.attackType)) {
      return false;
    }
    if (filters.alertStatus !== "all" && alertStatus !== filters.alertStatus) {
      return false;
    }
    if (filters.username && !username.includes(filters.username)) {
      return false;
    }
    if (Number.isFinite(filters.minRisk) && String(currentHuntMinRiskFilter || "").trim() !== "" && riskScore < filters.minRisk) {
      return false;
    }
    return true;
  }

  function collectHuntStatusOptions(alerts) {
    return [...new Set(
      (Array.isArray(alerts) ? alerts : [])
        .map(alert => String(alert.status || "").trim().toLowerCase())
        .filter(Boolean)
    )].sort((left, right) => left.localeCompare(right));
  }

  function refreshCurrentHuntResults() {
    if (!currentHuntQuery && !currentHuntPayload) {
      renderHuntView();
      return;
    }
    if (state.mode === "demo" || isDemoMode || !state.apiKey || !Array.isArray(currentHuntPayload?.base_alerts)) {
      currentHuntPayload = buildHuntLocalPayload(currentHuntQuery, currentHuntTimeRange);
    } else {
      currentHuntPayload = buildHuntPayloadFromBaseAlerts(currentHuntPayload.base_alerts, currentHuntQuery, currentHuntTimeRange);
    }
    huntResults = currentHuntPayload.alerts;
    renderHuntView();
  }

  function openHuntLinkedCase(caseId) {
    const normalizedCaseId = String(caseId || "").trim();
    if (!normalizedCaseId) {
      return;
    }
    setCurrentCaseSelection(normalizedCaseId, { suppressAutoSelect: false, preserveWorkspaceTab: true });
    showView("cases");
    renderCasesView();
  }

  function buildRelatedAlertsHuntQuery(alert) {
    const ip = String(alert?.ip || alert?.sourceIp || "").trim();
    const userId = String(alert?.userId || "").trim();
    if (ip && userId) {
      return `ip:${ip} OR user:${userId}`;
    }
    if (ip) {
      return `ip:${ip}`;
    }
    if (userId) {
      return `user:${userId}`;
    }
    return String(alert?.attackType || "").trim() ? `attack:${String(alert.attackType).trim()}` : "";
  }

  function buildHuntPayloadFromBaseAlerts(baseAlerts, query, timeRange) {
    const filteredAlerts = baseAlerts
      .filter(matchesHuntViewFilters);
    const alerts = sortHuntResults(
      filteredAlerts
    );
    const severityBreakdown = alerts.reduce((bucket, alert) => {
      const severity = String(alert.severity || "medium").toLowerCase();
      bucket[severity] = (bucket[severity] || 0) + 1;
      return bucket;
    }, {});
    const users = new Set(alerts.map(alert => String(alert.userId || "").trim()).filter(Boolean));
    const ips = new Set(alerts.map(alert => String(alert.sourceIp || "").trim()).filter(Boolean));
    return {
      query,
      parsed_query: parseHuntQuery(query, timeRange),
      time_range: timeRange || "24h",
      base_alerts: baseAlerts,
      alerts,
      total: alerts.length,
      stats: {
        unique_ips: ips.size,
        unique_users: users.size,
        severity_breakdown: severityBreakdown
      }
    };
  }

  function buildHuntLocalPayload(query, timeRange) {
    const sourceAlerts = getHuntSourceAlerts();
    const baseAlerts = filterAlertsByHuntQuery(sourceAlerts, query, timeRange)
      .map((alert, index) => normalizeHuntResult(alert, index))
      .map(alert => ({ ...alert, ...buildHuntCaseMeta(alert) }));
    return buildHuntPayloadFromBaseAlerts(baseAlerts, query, timeRange);
  }

  function getHuntSourceAlerts() {
    if (state.mode === "demo" || isDemoMode) {
      if (Array.isArray(state.alerts) && state.alerts.length) {
        return state.alerts.map(normalizeAlertModel);
      }
      if (Array.isArray(currentDemoAlerts) && currentDemoAlerts.length) {
        return currentDemoAlerts.map(normalizeAlertModel);
      }
      return demoAlerts.map(normalizeAlertModel);
    }
    if (Array.isArray(state.alerts) && state.alerts.length) {
      return state.alerts.map(normalizeAlertModel);
    }
    const panelAlerts = statsPanel.getAlerts?.();
    return Array.isArray(panelAlerts) ? panelAlerts.map(normalizeAlertModel) : [];
  }

  function normalizeHuntResult(alert, index = 0) {
    const normalizedAlert = normalizeAlertModel(alert);
    const sourceIp = String(normalizedAlert.sourceIp || normalizedAlert.source_ip || normalizedAlert.ip || "").trim();
    const destinationIp = String(
      normalizedAlert.destinationIp
      || normalizedAlert.destination_ip
      || normalizedAlert.details?.destination_ip
      || normalizedAlert.raw?.destination_ip
      || ""
    ).trim();
    const fallbackId = normalizedAlert.id || buildLocalAlertId({
      ...normalizedAlert,
      sourceIp,
      timestamp: normalizedAlert.timestamp || normalizedAlert.createdAt || normalizedAlert.created_at || 0
    }) || `hunt-${index}`;
    return {
      ...normalizedAlert,
      id: String(fallbackId),
      timestamp: normalizedAlert.timestamp || normalizedAlert.createdAt || normalizedAlert.created_at || 0,
      severity: String(normalizedAlert.severity || "medium").toLowerCase(),
      riskScore: Number(normalizedAlert.riskScore ?? normalizedAlert.risk_score ?? 0) || 0,
      attackType: String(normalizedAlert.attackType || normalizedAlert.attack_type || normalizedAlert.rule || "").trim(),
      sourceIp,
      destinationIp,
      ip: sourceIp || destinationIp,
      userId: String(normalizedAlert.userId || normalizedAlert.user_id || normalizedAlert.details?.user_id || "").trim(),
      country: String(normalizedAlert.country || normalizedAlert.enrichment?.country || "").trim(),
      status: String(normalizedAlert.status || normalizedAlert.lifecycle || "new").trim().toLowerCase(),
      caseId: String(normalizedAlert.caseId || normalizedAlert.case_id || "").trim(),
      investigationId: String(normalizedAlert.investigationId || normalizedAlert.investigation_id || "").trim()
    };
  }

  function renderHuntView() {
    if (huntQueryInputNode) {
      huntQueryInputNode.value = currentHuntQuery;
    }
    if (huntTimeRangeNode) {
      huntTimeRangeNode.value = currentHuntTimeRange;
    }
    if (huntSortNode) {
      huntSortNode.value = currentHuntSort;
    }
    if (huntCaseStatusNode) {
      huntCaseStatusNode.value = currentHuntCaseStatusFilter;
    }
    if (huntAttackFilterNode) {
      huntAttackFilterNode.value = currentHuntAttackFilter;
    }
    if (huntStatusFilterNode) {
      const availableStatuses = collectHuntStatusOptions(
        Array.isArray(currentHuntPayload?.base_alerts) ? currentHuntPayload.base_alerts : (Array.isArray(currentHuntPayload?.alerts) ? currentHuntPayload.alerts : huntResults)
      );
      const previousValue = currentHuntAlertStatusFilter || "all";
      huntStatusFilterNode.innerHTML = ['<option value="all">All</option>', ...availableStatuses.map(status => `<option value="${escapeHtml(status)}">${escapeHtml(status)}</option>`)].join("");
      huntStatusFilterNode.value = availableStatuses.includes(previousValue) || previousValue === "all" ? previousValue : "all";
      currentHuntAlertStatusFilter = String(huntStatusFilterNode.value || "all");
    }
    if (huntUserFilterNode) {
      huntUserFilterNode.value = currentHuntUserFilter;
    }
    if (huntMinRiskNode) {
      huntMinRiskNode.value = currentHuntMinRiskFilter;
    }
    if (!huntResultsBodyNode) {
      return;
    }
    const sortedResults = sortHuntResults(
      Array.isArray(currentHuntPayload?.alerts) ? currentHuntPayload.alerts : huntResults,
      currentHuntSort
    );
    if (huntStatusNode) {
      huntStatusNode.textContent = currentHuntQuery
        ? `Query: ${currentHuntQuery} | Window: ${currentHuntTimeRange}`
        : "Run a structured query from the global search bar";
    }
    if (huntSummaryNode) {
      const users = new Set(sortedResults.map(alert => String(alert.userId || "").trim()).filter(Boolean));
      const ips = new Set(
        sortedResults
          .flatMap(alert => [String(alert.sourceIp || "").trim(), String(alert.destinationIp || "").trim()])
          .filter(Boolean)
      );
      huntSummaryNode.textContent = currentHuntQuery
        ? (sortedResults.length
          ? `${sortedResults.length} matching alerts | ${ips.size} IPs | ${users.size} users`
          : "No matching alerts in the selected time range.")
        : "No hunt executed yet.";
    }
    if (!sortedResults.length) {
      huntResultsBodyNode.innerHTML = '<tr><td colspan="10" class="detail-empty-inline">No hunt results matched the current query.</td></tr>';
      return;
    }
    huntResultsBodyNode.innerHTML = sortedResults.map(alert => `
      <tr class="hunt-row" data-hunt-alert-id="${escapeHtml(String(alert.id || alert.alert_id || ""))}">
        <td>${escapeHtml(formatAbsoluteTime(alert.timestamp || 0))}</td>
        <td>${renderSeverityChip(alert.severity || "medium")}</td>
        <td>${renderHuntRiskScore(alert.riskScore || 0)}</td>
        <td><button type="button" class="hunt-pivot" data-hunt-field="attack" data-hunt-value="${escapeHtml(String(alert.attackType || ""))}">${escapeHtml(String(alert.attackType || "alert"))}</button></td>
        <td><button type="button" class="hunt-pivot" data-hunt-field="ip" data-hunt-value="${escapeHtml(String(alert.ip || ""))}">${escapeHtml(String(alert.ip || "unknown"))}</button></td>
        <td><button type="button" class="hunt-pivot" data-hunt-field="user" data-hunt-value="${escapeHtml(String(alert.userId || "Unknown"))}">${escapeHtml(String(alert.userId || "Unknown"))}</button></td>
        <td><button type="button" class="hunt-pivot" data-hunt-field="country" data-hunt-value="${escapeHtml(String(alert.country || ""))}">${escapeHtml(String(alert.country || "Unknown"))}</button></td>
        <td>${escapeHtml(String(alert.status || "new"))}</td>
        <td>${alert.caseId
          ? `<button type="button" class="hunt-inline-pivot" data-hunt-open-case="${escapeHtml(String(alert.caseId || ""))}">${escapeHtml(String(alert.caseLabel || "Linked case"))}</button>`
          : '<span class="panel-note">No case</span>'}</td>
        <td>
          <div class="hunt-actions">
            <button type="button" class="button hunt-action-button" data-hunt-action="open-investigation" data-hunt-alert-id="${escapeHtml(String(alert.id || ""))}">Open Investigation</button>
            ${alert.caseId
              ? `<button type="button" class="button hunt-action-button" data-hunt-action="open-case" data-hunt-case-id="${escapeHtml(String(alert.caseId || ""))}">Open Linked Case</button>`
              : `<button type="button" class="button hunt-action-button" data-hunt-action="create-case" data-hunt-alert-id="${escapeHtml(String(alert.id || ""))}">Create Case</button>`}
            <button type="button" class="button hunt-action-button" data-hunt-action="related-alerts" data-hunt-alert-id="${escapeHtml(String(alert.id || ""))}">View Related Alerts</button>
          </div>
        </td>
      </tr>
    `).join("");
    huntResultsBodyNode.querySelectorAll("[data-hunt-alert-id]").forEach(row => {
      row.addEventListener("click", event => {
        const target = event.target;
        if (target instanceof HTMLElement && target.closest(".hunt-pivot, .hunt-inline-pivot, [data-hunt-action]")) {
          return;
        }
        const alertId = row.getAttribute("data-hunt-alert-id");
        const directCase = sortedResults.find(alert => String(alert.id || "") === String(alertId || ""))?.caseId;
        if (directCase) {
          setCurrentCaseSelection(directCase, { suppressAutoSelect: false, preserveWorkspaceTab: true });
          showView("cases");
          renderCasesView();
          return;
        }
        const linkedCase = alertId ? selectLinkedCaseForAlert(state, alertId) : null;
        if (linkedCase?.id) {
          setCurrentCaseSelection(linkedCase.id, { suppressAutoSelect: false, preserveWorkspaceTab: true });
          showView("cases");
          renderCasesView();
          return;
        }
        window.openInvestigation?.(alertId, { forceVisible: true });
      });
    });
    huntResultsBodyNode.querySelectorAll(".hunt-pivot").forEach(button => {
      button.addEventListener("click", event => {
        event.stopPropagation();
        const nextQuery = buildPivotHuntQuery(button.getAttribute("data-hunt-field"), button.getAttribute("data-hunt-value"));
        runHuntQuery(nextQuery, currentHuntTimeRange).catch(error => {
          console.error(error);
        });
      });
    });
    huntResultsBodyNode.querySelectorAll("[data-hunt-open-case]").forEach(button => {
      button.addEventListener("click", event => {
        event.stopPropagation();
        openHuntLinkedCase(button.getAttribute("data-hunt-open-case"));
      });
    });
    huntResultsBodyNode.querySelectorAll("[data-hunt-action]").forEach(button => {
      button.addEventListener("click", async event => {
        event.stopPropagation();
        const action = String(button.getAttribute("data-hunt-action") || "");
        const alertId = String(button.getAttribute("data-hunt-alert-id") || "");
        const caseId = String(button.getAttribute("data-hunt-case-id") || "");
        const alert = sortedResults.find(entry => String(entry.id || "") === alertId) || null;
        if (action === "open-investigation" && alertId) {
          window.openInvestigation?.(alertId, { forceVisible: true });
          return;
        }
        if (action === "open-case" && caseId) {
          openHuntLinkedCase(caseId);
          return;
        }
        if (action === "create-case" && alertId) {
          await createCaseFromAlertWorkflow(alertId);
          refreshCurrentHuntResults();
          return;
        }
        if (action === "related-alerts" && alert) {
          const nextQuery = buildRelatedAlertsHuntQuery(alert);
          if (!nextQuery) {
            showToast("No related alert query available");
            return;
          }
          await runHuntQuery(nextQuery, currentHuntTimeRange, { forceView: false });
        }
      });
    });
  }

  async function runHuntQuery(query, timeRange = currentHuntTimeRange, { forceView = true } = {}) {
    const normalizedQuery = String(query || "").trim();
    const normalizedTimeRange = String(timeRange || "24h").trim().toLowerCase() || "24h";
    currentHuntQuery = normalizedQuery;
    currentHuntTimeRange = normalizedTimeRange;
    if (globalSearchNode) {
      globalSearchNode.value = normalizedQuery;
    }
    if (huntQueryInputNode) {
      huntQueryInputNode.value = normalizedQuery;
    }
    if (huntTimeRangeNode) {
      huntTimeRangeNode.value = normalizedTimeRange;
    }
    const localPayload = buildHuntLocalPayload(normalizedQuery, normalizedTimeRange);
    if (state.mode === "demo" || !state.apiKey) {
      huntResults = localPayload.alerts;
      currentHuntPayload = localPayload;
      if (forceView) {
        showView("hunt");
      } else {
        renderHuntView();
      }
      return localPayload;
    }
    try {
      const payload = await requestJson(`/search?mode=hunt&q=${encodeURIComponent(normalizedQuery)}&time_range=${encodeURIComponent(normalizedTimeRange)}`);
      const baseAlerts = Array.isArray(payload.alerts)
        ? payload.alerts.map(normalizeAlertModel).map((alert, index) => normalizeHuntResult(alert, index)).map(alert => ({ ...alert, ...buildHuntCaseMeta(alert) }))
        : [];
      currentHuntPayload = {
        ...payload,
        ...buildHuntPayloadFromBaseAlerts(baseAlerts, normalizedQuery, normalizedTimeRange)
      };
      huntResults = currentHuntPayload.alerts;
      if (forceView) {
        showView("hunt");
      } else {
        renderHuntView();
      }
      return payload;
    } catch (error) {
      huntResults = localPayload.alerts;
      currentHuntPayload = localPayload;
      if (forceView) {
        showView("hunt");
      } else {
        renderHuntView();
      }
      if (huntStatusNode) {
        huntStatusNode.textContent = `Local results only: ${error.message || "hunt failed"}`;
      }
      return localPayload;
    }
  }

  window.launchHuntQuery = (query, timeRange = currentHuntTimeRange) => {
    runHuntQuery(query, timeRange).catch(error => {
      console.error(error);
    });
  };

  function getPlaybookByKey(playbookKey) {
    return playbookDefinitions.find(playbook => String(playbook.key || playbook.id) === String(playbookKey || "")) || null;
  }

  async function applyDemoPlaybookExecution(alertId, playbookKey, { automatic = false } = {}) {
    const playbook = getPlaybookByKey(playbookKey);
    const alert = findAlertByAnyId(alertId);
    if (!playbook || !alert) {
      return null;
    }
    const actor = automatic ? "system" : (state.user?.username || currentUser?.username || "analyst");
    const execution = {
      execution_id: `demo-pbx-${Date.now()}`,
      playbook_id: playbook.id || playbook.playbook_id || playbook.key,
      playbook_key: playbook.key || playbook.id,
      alert_id: String(alert.id || ""),
      automatic,
      actor,
      status: "success",
      started_at: Date.now() / 1000,
      steps: []
    };

    for (const action of Array.isArray(playbook.actions) ? playbook.actions : []) {
      const actionType = String(action.type || "").toLowerCase();
      if (actionType === "create_case") {
        await createCaseFromAlertWorkflow(String(alert.id || ""));
        execution.steps.push({ type: actionType, status: "success", result: { caseId: findAlertByAnyId(alert.id)?.caseId || null } });
        continue;
      }
      if (actionType === "assign_analyst") {
        await window.assignAnalyst?.(String(alert.id || ""), state.user?.username || currentUser?.username || "analyst");
        execution.steps.push({ type: actionType, status: "success", result: { assignedTo: state.user?.username || currentUser?.username || "analyst" } });
        continue;
      }
      if (actionType === "block_ip") {
        await window.blockIp?.(alert.sourceIp || alert.source_ip || alert.ip);
        execution.steps.push({ type: actionType, status: "success", result: { ip: alert.sourceIp || alert.source_ip || alert.ip } });
        continue;
      }
      if (actionType === "suppress_alert") {
        applyDemoAlertUpdate(candidate => {
          if (String(candidate.id || "") !== String(alert.id || "")) {
            return false;
          }
          candidate.disposition = "suppressed";
          candidate.status = "new";
          candidate.raw = {
            ...(candidate.raw || {}),
            disposition: "suppressed"
          };
          return true;
        });
        appendDemoAudit("suppress_alert", String(alert.id || ""));
        execution.steps.push({ type: actionType, status: "success", result: { suppressed: true } });
        continue;
      }
      if (actionType === "enrich_ip" || actionType === "check_threat_intel") {
        appendActivityLog("playbook_step", "playbook", String(alert.id || ""), `${actionType} for ${alert.sourceIp || "unknown"}`);
        execution.steps.push({ type: actionType, status: "success", result: { ip: alert.sourceIp || alert.source_ip || alert.ip || "" } });
        continue;
      }
    }

    execution.completed_at = Date.now() / 1000;
    playbookExecutions = [execution, ...playbookExecutions].slice(0, 50);
    const linkedCase = selectLinkedCaseForAlert(state, String(alert.id || ""))
      || casesCache.find(entry =>
        String(entry?.source_alert_id || entry?.alert_id || entry?.sourceAlertId || "") === String(alert.id || "")
      )
      || null;
    if (linkedCase?.id) {
      const impactedEntities = execution.steps
        .map(step => getPlaybookStepResultValue(step, ["ip", "assignedTo", "caseId", "case_id"]))
        .filter(Boolean);
      const playbookTimelineEvent = createCaseTimelineEntry("playbook_executed", {
        playbook: execution.playbook_key || execution.playbook_id,
        status: execution.status,
        entities: impactedEntities
      }, actor, execution.completed_at);
      const playbookCaseAction = buildCaseAction(
        "playbook_execution",
        linkedCase,
        `${automatic ? "Automatic" : "Manual"} playbook ${execution.playbook_key || execution.playbook_id} executed for case ${linkedCase.title || linkedCase.id}`,
        { alertId: String(alert.id || "") },
        {
          playbook: execution.playbook_key || execution.playbook_id,
          status: execution.status,
          entities: impactedEntities
        }
      );
      appendCaseActionToDemo(linkedCase.id, playbookCaseAction, null, [playbookTimelineEvent]);
    }
    appendActivityLog("playbook_execution", "playbook", execution.playbook_id, `${automatic ? "Automatic" : "Manual"} playbook on alert ${alert.id}`);
    renderAdminSocView();
    return execution;
  }

  async function autoRunDemoPlaybooks() {
    const candidate = (Array.isArray(state.alerts) ? state.alerts : []).find(alert =>
      !autoExecutedDemoPlaybooks.has(String(alert.id || ""))
      && String(alert.attackType || alert.attack_type || alert.rule || "").toLowerCase() === "honeypot_access"
    );
    if (!candidate) {
      return;
    }
    autoExecutedDemoPlaybooks.add(String(candidate.id || ""));
    await applyDemoPlaybookExecution(String(candidate.id || ""), "credential_containment", { automatic: true });
  }

  window.runAlertPlaybook = async (alertId, playbookKey, options = {}) => {
    if (state.mode === "demo" || !state.apiKey) {
      if (!playbookDefinitions.length) {
        await loadPlaybooks().catch(() => {});
      }
      if (!playbookDefinitions.length) {
        showToast("No demo playbooks available");
        return { ok: false, code: "missing_playbooks", reason: "No demo playbooks available" };
      }
      const runState = getPlaybookRunState(alertId, playbookKey || "credential_containment", {
        origin: options.source || state.currentView || "investigations",
        caseRecord: options.caseRecord || null
      });
      if (!runState.canRun) {
        showToast(runState.reason || "Playbook rerun is blocked");
        return { ok: false, code: runState.code || "blocked", reason: runState.reason || "Playbook rerun is blocked" };
      }
      const execution = await applyDemoPlaybookExecution(String(alertId || ""), playbookKey || "credential_containment", { automatic: false });
      if (execution) {
        showToast(`Playbook ${execution.playbook_id} executed`);
        if (options.source === "cases" || state.currentView === "cases") {
          if (options.caseId) {
            setCurrentCaseSelection(options.caseId, { suppressAutoSelect: false, preserveWorkspaceTab: true });
          }
          selectedCaseWorkspaceTab = "overview";
          renderCasesView();
        }
        renderInvestigationsView();
        return { ok: true, code: "executed", execution };
      } else {
        showToast("Could not run playbook for this case");
        return { ok: false, code: "execution_failed", reason: "Could not run playbook for this case" };
      }
    }
    try {
      requireAuth();
    } catch {
      return { ok: false, code: "auth_required", reason: "Authentication required" };
    }
    try {
      const payload = await requestJson("/playbooks/run", {
        method: "POST",
        body: JSON.stringify({ alert_id: alertId, playbook_key: playbookKey || null })
      });
      await loadSnapshot("manual");
      await loadPlaybooks();
      await loadAuditLogs();
      if (options.source === "cases" || state.currentView === "cases") {
        if (options.caseId) {
          setCurrentCaseSelection(options.caseId, { suppressAutoSelect: false, preserveWorkspaceTab: true });
        }
        selectedCaseWorkspaceTab = "overview";
        renderCasesView();
      }
      if (payload?.alert?.id) {
        openInvestigationAlert(payload.alert.id, { forceVisible: false });
      } else {
        renderInvestigationsView();
      }
      showToast(`Playbook ${payload?.execution?.playbook_id || playbookKey} executed`);
      return { ok: true, code: "executed", payload };
    } catch (error) {
      console.error(error);
      showToast(error.message || "Failed to run playbook");
      return { ok: false, code: "request_failed", reason: error.message || "Failed to run playbook" };
    }
  };

  window.runCasePlaybook = async (caseId, playbookKey = null) => {
    const caseRecord = casesCache.find(entry => String(entry?.id || "") === String(caseId || ""));
    if (!caseRecord) {
      showToast("Case not found");
      return;
    }
    const alertId = resolveCasePlaybookAlertId(caseRecord);
    if (!alertId) {
      showToast("No linked alert available for this case");
      return;
    }
    const resolvedPlaybook = playbookKey || playbookDefinitions[0]?.key || playbookDefinitions[0]?.id || "credential_containment";
    const normalizedCaseId = String(caseRecord.id || "");
    const currentUiState = getCasePlaybookUiState(normalizedCaseId);
    if (currentUiState.isRunning) {
      return;
    }
    setCasePlaybookUiState(normalizedCaseId, { isRunning: true, lastError: "", lastAction: "run" });
    if (state.currentView === "cases") {
      renderCasesView();
    }
    try {
      const result = await window.runAlertPlaybook?.(alertId, resolvedPlaybook, {
        caseId: caseRecord.id,
        caseRecord,
        source: "cases"
      });
      if (result?.ok) {
        clearCasePlaybookUiState(normalizedCaseId);
        return result;
      }
      setCasePlaybookUiState(normalizedCaseId, {
        isRunning: false,
        lastAction: "",
        lastError: result?.code === "blocked" || result?.code === "ip_still_blocked" || result?.code === "missing_alert" || result?.code === "false_positive" || result?.code === "closed" || result?.code === "suppressed"
          ? ""
          : String(result?.reason || "Failed to run playbook")
      });
      return result;
    } catch (error) {
      console.error(error);
      setCasePlaybookUiState(normalizedCaseId, {
        isRunning: false,
        lastAction: "",
        lastError: error?.message || "Failed to run playbook"
      });
      throw error;
    } finally {
      const latestUiState = getCasePlaybookUiState(normalizedCaseId);
      if (latestUiState.isRunning) {
        setCasePlaybookUiState(normalizedCaseId, { isRunning: false, lastAction: "" });
      }
      if (state.currentView === "cases") {
        renderCasesView();
      }
    }
  };

  function renderSearchResults(payload, query) {
    if (!searchPanelNode || !searchResultsNode || !searchStatusNode) {
      return;
    }

    if (!query) {
      searchPanelNode.style.display = "none";
      searchResultsNode.innerHTML = "";
      return;
    }

    const alerts = (Array.isArray(payload.alerts) ? payload.alerts : []).slice(0, 8);
    const investigations = Array.isArray(payload.investigations) ? payload.investigations : [];
    const cases = Array.isArray(payload.cases) ? payload.cases : [];
    const totalMatches = alerts.length + investigations.length + cases.length;
    searchPanelNode.style.display = "block";
    searchStatusNode.textContent = totalMatches ? `${totalMatches} matches` : "No results found";

    const resolveAlertSearchId = alert => {
      const directId = String(alert?.id || alert?.alert_id || "");
      if (directId && statsPanel.getAlertById?.(directId)) {
        return directId;
      }

      const localId = buildLocalAlertId(alert);
      if (localId && statsPanel.getAlertById?.(localId)) {
        return localId;
      }

      const sourceIp = String(alert?.sourceIp || alert?.source_ip || alert?.ip || "");
      const attackType = String(alert?.attackType || alert?.attack_type || alert?.rule || "alert");
      const timestamp = Number(alert?.timestamp || alert?.createdAt || alert?.created_at || 0);
      const matchedAlert = (statsPanel.getAlerts?.() || []).find(entry =>
        (directId && String(entry.raw?.id || entry.id || "") === directId) ||
        (
          entry.sourceIp === sourceIp &&
          entry.attackType === attackType &&
          Math.abs(Number(entry.timestamp || 0) - timestamp) < 1000
        )
      );

      return matchedAlert?.id || directId || localId;
    };

    const renderGroup = (title, items, mapper) => items.length ? `
      <div class="search-group">
        <div class="search-group-title">${escapeHtml(title)}</div>
        ${items.map(mapper).join("")}
      </div>
    ` : "";

    searchResultsNode.innerHTML = [
      renderGroup("Alerts", alerts, (alert, index) => `
        <button type="button" class="search-result-item" data-kind="alert" data-index="${escapeHtml(String(index))}" data-id="${escapeHtml(String(alert.id || alert.alert_id || ""))}">
          <div class="search-result-top">
            <strong>${escapeHtml(alert.attackType || alert.attack_type || alert.rule || "Alert")}</strong>
            <span class="record-badge">${escapeHtml(String(alert.severity || "medium").toUpperCase())}</span>
          </div>
          <div class="search-result-copy">
            <span>${escapeHtml(alert.sourceIp || alert.source_ip || alert.ip || "unknown")}</span>
            <span class="feed-meta">${escapeHtml(alert.country || "Unknown")} · ${escapeHtml(String(alert.status || "open"))}</span>
          </div>
        </button>
      `),
      renderGroup("Investigations", investigations, investigation => `
        <button type="button" class="search-result-item" data-kind="investigation" data-id="${escapeHtml(investigation.id)}">
          <div class="search-result-top">
            <strong>${escapeHtml(investigation.title || "Investigation")}</strong>
            <span class="record-badge">${escapeHtml(String(investigation.status || "open").toUpperCase())}</span>
          </div>
          <div class="search-result-copy">
            <span>${escapeHtml(investigation.analyst || "Unassigned")}</span>
            <span class="feed-meta">${escapeHtml(investigation.alert_id || "No alert linked")}</span>
          </div>
        </button>
      `),
      renderGroup("Cases", cases, caseRecord => `
        <button type="button" class="search-result-item" data-kind="case" data-id="${escapeHtml(caseRecord.id)}">
          <div class="search-result-top">
            <strong>${escapeHtml(caseRecord.title || "Case")}</strong>
            ${buildPriorityBadge(caseRecord.priority)}
          </div>
          <div class="search-result-copy">
            <span>${escapeHtml(caseRecord.assignee || "Unassigned")}</span>
            <span class="feed-meta">${escapeHtml(String(caseRecord.status || "open").toUpperCase())}</span>
          </div>
        </button>
      `)
    ].filter(Boolean).join("") || `<div class="search-empty">No results found for "${escapeHtml(query)}".</div>`;

    searchResultsNode.querySelectorAll('[data-kind="alert"]').forEach(button => {
      const index = Number(button.getAttribute("data-index") || "-1");
      const alert = alerts[index];
      if (!alert) {
        return;
      }
      button.setAttribute("data-id", resolveAlertSearchId(alert));
    });

    searchResultsNode.querySelectorAll("[data-kind]").forEach(button => {
      button.addEventListener("click", async () => {
        const kind = button.getAttribute("data-kind");
        const id = button.getAttribute("data-id");
        if (kind === "alert") {
          openInvestigationAlert(id, { forceVisible: true });
          return;
        }
        if (kind === "investigation") {
          const record = investigationsCache.find(entry => entry.id === id) || investigations.find(entry => entry.id === id);
          if (record?.alert_id) {
            window.openInvestigation?.(record.alert_id);
          } else {
            showView("investigations");
          }
          return;
        }
        setCurrentCaseSelection(id, { preserveWorkspaceTab: true });
        if (!casesCache.some(entry => entry.id === id)) {
          casesCache = cases;
        }
        showView("cases");
      });
    });
  }

  async function executeSearch(query) {
    const normalizedQuery = String(query || "").trim();
    if (!normalizedQuery) {
      renderSearchResults({ alerts: [], investigations: [], cases: [], total: 0 }, "");
      return;
    }

    const looksStructured = /(^|\s)(ip|user|attack|country|severity|status):/i.test(normalizedQuery)
      || /\s+(AND|OR)\s+/i.test(normalizedQuery)
      || /\blast\s+(5\s*(?:m|min|mins|minute|minutes)|1\s*(?:h|hr|hour|hours)|24\s*(?:h|hr|hour|hours))\b/i.test(normalizedQuery);
    if (looksStructured) {
      renderSearchResults({ alerts: [], investigations: [], cases: [], total: 0 }, "");
      return;
    }

    const getLocalSearchPayload = () => {
      const lowered = normalizedQuery.toLowerCase();
      const canonicalAlerts = Array.isArray(state.alerts) && state.alerts.length
        ? state.alerts
        : (statsPanel.getAlerts?.() || []);
      const alerts = filterAlertsForSearch(canonicalAlerts, normalizedQuery).slice(0, 8);
      const containsQuery = value => JSON.stringify(value || "").toLowerCase().includes(lowered);
      const investigations = investigationsCache.filter(containsQuery).slice(0, 10);
      const cases = casesCache.filter(containsQuery).slice(0, 10);
      return {
        alerts,
        investigations,
        cases,
        total: alerts.length + investigations.length + cases.length
      };
    };

    const localPayload = getLocalSearchPayload();
    if (state.mode === "demo" || !state.apiKey) {
      renderSearchResults(localPayload, normalizedQuery);
      return;
    }

    try {
      const payload = await requestJson(`/search?q=${encodeURIComponent(normalizedQuery)}`);
      const mergedPayload = {
        alerts: localPayload.alerts,
        investigations: Array.isArray(payload.investigations) && payload.investigations.length ? payload.investigations : localPayload.investigations,
        cases: Array.isArray(payload.cases) && payload.cases.length ? payload.cases : localPayload.cases
      };
      mergedPayload.total = mergedPayload.alerts.length + mergedPayload.investigations.length + mergedPayload.cases.length;
      renderSearchResults(mergedPayload, normalizedQuery);
    } catch (error) {
      renderSearchResults(localPayload, normalizedQuery);
      searchStatusNode.textContent = localPayload.total
        ? `Local results only: ${error.message || "Search failed"}`
        : (error.message || "Search failed");
    }
  }

  window.blockIp = async ip => {
    try {
      requireAuth();
    } catch {
      return;
    }
    if (state.mode === "demo") {
      console.log("Demo mode: block IP action executed while demo data remains static");
      applyDemoAlertUpdate(alert => {
        if ((alert.sourceIp || alert.ip) !== ip) {
          return false;
        }
        alert.is_blocked = true;
        return true;
      });
      markIpBlockedLocally(ip);
      appendDemoAudit("block_ip", ip);
      renderAdminSocView();
      showToast("IP blocked");
      return;
    }
    if (!config.apiKey) {
      window.alert("Enter API key before blocking an IP.");
      endPendingCaseAction(pendingKey);
      return;
    }

    try {
      const payload = await blockIpAddress(config.apiBaseUrl, config.apiKey, ip);
      markIpBlockedLocally(ip);
      renderAdminSocView();
      showToast(payload?.action === "already_blocked" ? `IP ${ip} already blocked` : `IP ${ip} blocked`);
      await loadSnapshot("manual");
    } catch (error) {
      console.error(error);
      window.alert(error.message || "Failed to block IP");
    }
  };

  window.unblockIp = async ip => {
    const normalizedIp = String(ip || "").trim();
    if (!normalizedIp) {
      return;
    }
    if (state.mode !== "demo" && !state.apiKey) {
      showToast("Unblock is only available in demo mode right now");
      return;
    }
    unmarkIpBlockedLocally(normalizedIp);
    clearCasePlaybookUiStateForIp(normalizedIp);
    appendActivityLog("unblock_ip", "playbook", normalizedIp, `Removed block for ${normalizedIp}`);
    if (state.mode === "demo") {
      applyDemoAlertUpdate(alert => {
        if ((alert.sourceIp || alert.ip) !== normalizedIp) {
          return false;
        }
        alert.is_blocked = false;
        alert.isBlocked = false;
        return true;
      });
      appendDemoUnblockActivity(normalizedIp);
    }
    if (state.currentView === "cases") {
      renderCasesView();
    }
    renderInvestigationsView();
    renderAdminSocView();
    showToast(`IP ${normalizedIp} unblocked`);
  };

  async function blockIpFromCaseWorkflow(caseId) {
    const caseRecord = casesCache.find(entry => String(entry.id) === String(caseId));
    if (!caseRecord) {
      window.alert("Case not found");
      return;
    }
    const ip = getCaseBlockableIp(caseRecord);
    if (!ip) {
      showToast("No source IP available for this case");
      return;
    }
    if (!window.confirm(`Block IP ${ip}?`)) {
      return;
    }
    const pendingKey = beginPendingCaseAction("block_ip", caseId);
    if (!pendingKey) {
      return;
    }

    try {
      requireAuth();
    } catch {
      endPendingCaseAction(pendingKey);
      return;
    }

    const blockAction = buildCaseAction(
      "block_ip",
      caseRecord,
      `${getCurrentActor()} blocked IP ${ip} from case ${caseRecord.title || caseId}`,
      { ip },
      { ip }
    );

    if (state.mode === "demo") {
      applyDemoAlertUpdate(alert => {
        if ((alert.sourceIp || alert.source_ip || alert.ip) !== ip) {
          return false;
        }
        alert.is_blocked = true;
        return true;
      });
      markIpBlockedLocally(ip);
      applyWorkflowState(workflowCommands.blockIpFromCase(state, ip));
      appendCaseActionToDemo(caseId, blockAction);
      renderCasesView();
      renderAdminSocView();
      dispatchSocAction(blockAction);
      showToast(`IP ${ip} blocked`);
      endPendingCaseAction(pendingKey);
      return;
    }

    if (!config.apiKey) {
      window.alert("Enter API key before blocking an IP.");
      endPendingCaseAction(pendingKey);
      return;
    }

    try {
      const payload = await blockIpAddress(config.apiBaseUrl, config.apiKey, ip);
      markIpBlockedLocally(ip);
      applyWorkflowState(workflowCommands.blockIpFromCase(state, ip));
      await persistCaseAction(caseId, {
        action: {
          ...blockAction,
          result: { ip, outcome: payload?.action || "blocked" },
          message: payload?.action === "already_blocked"
            ? `${getCurrentActor()} attempted to block IP ${ip} from case ${caseRecord.title || caseId} - already blocked`
            : blockAction.message
        }
      });
      await loadCases();
      await loadInvestigations();
      await loadAuditLogs();
      renderAdminSocView();
      if (state.currentView === "cases") {
        renderCasesView();
      }
      dispatchSocAction({
        ...blockAction,
        result: { ip, outcome: payload?.action || "blocked" },
        message: payload?.action === "already_blocked"
          ? `${getCurrentActor()} attempted to block IP ${ip} from case ${caseRecord.title || caseId} - already blocked`
          : blockAction.message
      });
      showToast(payload?.action === "already_blocked" ? `IP ${ip} already blocked` : `IP ${ip} blocked`);
    } catch (error) {
      console.error(error);
      window.alert(error.message || "Failed to block IP");
    } finally {
      endPendingCaseAction(pendingKey);
    }
  }

  window.blockCaseIp = async caseId => {
    await blockIpFromCaseWorkflow(caseId);
  };

  async function markAlertFalsePositiveWorkflow(id) {
    try {
      requireAuth();
    } catch {
      return;
    }
    const frontendAlertId = getFrontendAlertId(id);
    const alert = statsPanel.getAlertById?.(frontendAlertId);
    if (!alert || normalizeAlertLifecycle(alert) === "false_positive") {
      return;
    }
    const pendingKey = beginPendingAlertAction("false_positive", frontendAlertId);
    if (!pendingKey) {
      return;
    }
    if (isDemoMode && !allowActionsInDemo) {
      window.alert("Incident actions are disabled in demo mode.");
      endPendingAlertAction(pendingKey);
      return;
    }
    try {
      let linkedCase = selectLinkedCaseForAlert(state, frontendAlertId)
        || casesCache.find(entry =>
          String(entry.id || "") === String(alert.caseId || alert.case_id || alert.mergedIntoCaseId || alert.merged_into_case_id || "")
          || String(entry.source_alert_id || entry.alert_id || entry.sourceAlertId || "") === frontendAlertId
        )
        || null;
      if (!linkedCase && state.mode === "demo") {
        await createCaseFromAlertWorkflow(frontendAlertId);
        linkedCase = selectLinkedCaseForAlert(state, frontendAlertId)
          || casesCache.find(entry =>
            String(entry.source_alert_id || entry.alert_id || entry.sourceAlertId || "") === frontendAlertId
          )
          || null;
      }

      if (linkedCase) {
        await markCaseFalsePositiveWorkflow(linkedCase.id, { sourceAlertId: frontendAlertId });
        return;
      }

      await markAlertOnlyFalsePositiveWorkflow(frontendAlertId);
    } catch (error) {
      console.error(error);
      window.alert(error.message || "Failed to mark false positive");
    } finally {
      endPendingAlertAction(pendingKey);
    }
  }

  window.markFalsePositive = async id => {
    await markAlertFalsePositiveWorkflow(id);
  };

  window.addToWatchlist = async (type, value) => {
    const normalizedType = String(type || "").trim().toLowerCase();
    const normalizedValue = String(value || "").trim();
    if (!normalizedType || !normalizedValue) {
      return;
    }
    try {
      requireAuth();
      await requestJson("/watchlist/add", {
        method: "POST",
        body: JSON.stringify({ type: normalizedType, value: normalizedValue })
      });
      await loadWatchlist();
      await loadSnapshot("manual");
      if (state.currentView === "investigations") {
        renderInvestigationsView();
      } else if (state.currentView === "dashboard") {
        renderDashboardView();
      }
      if (iocPivotState.open && iocPivotState.payload?.ioc?.value) {
        openIocPivot(iocPivotState.payload.ioc.type, iocPivotState.payload.ioc.value, iocPivotState.source);
      }
      showToast(`Added ${normalizedValue} to watchlist`);
    } catch (error) {
      console.error(error);
      window.alert(error.message || "Failed to add watchlist entry");
    }
  };

  window.removeFromWatchlist = async (type, value) => {
    const normalizedType = String(type || "").trim().toLowerCase();
    const normalizedValue = String(value || "").trim();
    if (!normalizedType || !normalizedValue) {
      return;
    }
    try {
      requireAuth();
      await requestJson("/watchlist/remove", {
        method: "DELETE",
        body: JSON.stringify({ type: normalizedType, value: normalizedValue })
      });
      await loadWatchlist();
      await loadSnapshot("manual");
      if (state.currentView === "investigations") {
        renderInvestigationsView();
      } else if (state.currentView === "dashboard") {
        renderDashboardView();
      }
      if (iocPivotState.open && iocPivotState.payload?.ioc?.value) {
        openIocPivot(iocPivotState.payload.ioc.type, iocPivotState.payload.ioc.value, iocPivotState.source);
      }
      showToast(`Removed ${normalizedValue} from watchlist`);
    } catch (error) {
      console.error(error);
      window.alert(error.message || "Failed to remove watchlist entry");
    }
  };

  window.assignAnalyst = async (id, analyst) => {
    if (!analyst) {
      return;
    }
    try {
      requireAuth();
    } catch {
      return;
    }
    selectedAnalystByAlert[id] = analyst;
    if (state.mode === "demo") {
      console.log("Demo mode: assign analyst action executed while demo data remains static");
      applyDemoAlertUpdate(alert => {
        if (buildLocalAlertId(alert) !== id) {
          return false;
        }
        alert.analyst = analyst;
        return true;
      });
      appendDemoAudit("assign_alert", `${id}:${analyst}`);
      if (analyst === state.user?.username) {
        showToast("Assigned to you");
      } else {
        showToast(`Assigned to ${analyst}`);
      }
      return;
    }
    if (!config.apiKey) {
      window.alert("Enter API key before assigning an analyst.");
      return;
    }

    try {
      await postAlertAction(config.apiBaseUrl, config.apiKey, "/actions/assign", { id, analyst });
      if (analyst === state.user?.username) {
        showToast("Assigned to you");
      } else {
        showToast(`Assigned to ${analyst}`);
      }
      await loadSnapshot("manual");
    } catch (error) {
      console.error(error);
      window.alert(error.message || "Failed to assign analyst");
    }
  };

  window.assignCaseToAnalyst = async id => {
    try {
      requireAuth();
      requireAdmin();
    } catch {
      return;
    }

    const selectNode = document.getElementById(`admin-assign-${id}`);
    const analyst = selectNode?.value?.trim() || "";
    if (!analyst) {
      window.alert("Select an analyst first");
      return;
    }

    await window.assignAnalyst?.(id, analyst);
  };

  window.pickUpCase = async id => {
    const user = window.__dashboardGetCurrentUser?.();
    const username = user?.username;
    if (!username) {
      window.alert("You must be logged in");
      return;
    }
    const alert = statsPanel.getAlertById?.(id);
    if (alert?.analyst && alert.analyst !== username) {
      window.alert(`Already assigned to ${alert.analyst}`);
      return;
    }
    await window.assignAnalyst?.(id, username);
    const assignedUserNode = document.getElementById("assigned-user");
    const pickupButtonNode = document.getElementById("pickup-btn");
    if (assignedUserNode) {
      assignedUserNode.textContent = `Assigned to: ${username}`;
    }
    if (pickupButtonNode) {
      pickupButtonNode.disabled = true;
      pickupButtonNode.textContent = "Case claimed";
    }
  };

  window.addAlertNote = async id => {
    const input = document.getElementById(`note-input-${id}`);
    const note = input?.value.trim() || "";
    if (!note) {
      return;
    }
    try {
      requireAuth();
    } catch {
      return;
    }
    if (isDemoMode && !allowActionsInDemo) {
      window.alert("Incident actions are disabled in demo mode.");
      return;
    }
    if (isDemoMode) {
      console.log("Demo mode: add note action executed while demo data remains static");
      applyDemoAlertUpdate(alert => {
        if (buildLocalAlertId(alert) !== id) {
          return false;
        }
        alert.notes = Array.isArray(alert.notes) ? alert.notes : [];
        alert.notes.push({
          text: note,
          timestamp: Date.now()
        });
        return true;
      });
      if (input) {
        input.value = "";
      }
      appendDemoAudit("add_note", id);
      window.alert("Note added");
      return;
    }
    if (!config.apiKey) {
      window.alert("Enter API key before adding a note.");
      return;
    }

    try {
      await postAlertAction(config.apiBaseUrl, config.apiKey, "/actions/add-note", { id, note });
      if (input) {
        input.value = "";
      }
      window.alert("Note added");
      await loadSnapshot("manual");
    } catch (error) {
      console.error(error);
      window.alert(error.message || "Failed to add note");
    }
  };

  window.investigateAlertContext = async id => {
    console.log("INVESTIGATE_CLICKED");
    console.log("INVESTIGATE_HANDLER:investigateAlertContext");
    console.log("STATE_ALERTS_LENGTH_BEFORE", state.alerts.length);
    console.log("FILTERED_ALERTS_LENGTH", state.filteredAlerts.length);
    const context = focusInvestigationContext(id);
    if (!context) {
      window.alert("Alert not found");
      return;
    }

    console.log("SHOWVIEW_CALLED", false);
    if (state.currentView !== "investigations") {
      activateViewFrame("investigations");
    }
    console.log("INVESTIGATE_HANDLER:renderInvestigationsView");
    renderInvestigationsView();
    statsPanel.selectAlert?.(context.selectedAlertId, { notifySelection: false });
    syncFilteredAlertsState();
    console.log("STATE_ALERTS_LENGTH_AFTER", state.alerts.length);
    appendActivityLog("investigate", "investigation", context.selectedAlertId, context.entityKey);
    scrollSelectedInvestigationContext(context.selectedAlertId);
    showToast("Investigation workspace opened");
  };

  async function createCaseFromAlertWorkflow(id, options = {}) {
    const frontendAlertId = getFrontendAlertId(id);
    const alert = statsPanel.getAlertById?.(frontendAlertId);
    if (!alert) {
      window.alert("Alert not found");
      return;
    }
    try {
      requireAuth();
    } catch {
      return;
    }

    if (isAlertEscalatedToCase(alert)) {
      showToast("Case already exists");
      return;
    }
    const pendingKey = beginPendingAlertAction("create_case", frontendAlertId);
    if (!pendingKey) {
      return;
    }
    const actor = getCurrentActor();
    try {
      if (state.mode === "demo") {
        const existingCase = casesCache.find(entry => entry.alert_id === frontendAlertId);
        const createdAt = Date.now() / 1000;
        const creationTimeline = buildCaseCreationTimeline(alert, `case-${frontendAlertId}`, actor, createdAt);
        const createAction = buildActionObject({
          actionType: "create_case",
          actor,
          targetType: "case",
          targetId: `case-${frontendAlertId}`,
          relatedCaseId: `case-${frontendAlertId}`,
          relatedAlertId: frontendAlertId,
          input: { alertId: frontendAlertId },
          result: { caseId: `case-${frontendAlertId}`, lifecycle: "in_case" },
          message: `${actor} created case from alert ${frontendAlertId}`
        });
        if (!existingCase) {
          setCasesState([{
            id: `case-${frontendAlertId}`,
            title: `${alert.attackType} case`,
            summary: `Demo case created for ${alert.sourceIp}`,
            source_alert_id: frontendAlertId,
            alert_id: frontendAlertId,
            source_investigation_id: `inv-${frontendAlertId}`,
            investigation_id: `inv-${frontendAlertId}`,
            priority: alert.severity || "medium",
            severity: alert.severity || "medium",
            status: "open",
            assignee: state.user?.username || null,
            linked_alert_ids: [frontendAlertId],
            notes: [],
            actions: [createAction],
            timeline: creationTimeline,
            evidence: {
              timeline: [createAction],
              enrichments: [{
                timestamp: createdAt,
                source: "source_alert",
                snapshot: {
                  id: frontendAlertId,
                  source_ip: alert.sourceIp,
                  attack_type: alert.attackType,
                  severity: alert.severity,
                  risk_score: alert.riskScore,
                  country: alert.country,
                  disposition: alert.disposition
                }
              }],
              analyst_notes: []
            },
            created_at: createdAt,
            updated_at: createdAt,
            alert: {
              id: frontendAlertId,
              source_ip: alert.sourceIp,
              attack_type: alert.attackType,
              severity: alert.severity
            }
          }, ...casesCache]);
        }
        const createdCaseId = casesCache.find(entry => entry.alert_id === frontendAlertId)?.id || null;
        markAlertCaseCreatedLocally(frontendAlertId, {
          caseId: createdCaseId,
          investigationId: `inv-${frontendAlertId}`
        });
        if (state.currentView === "investigations") {
          renderInvestigationsView();
        }
        if (state.currentView === "cases" && createdCaseId) {
          setCurrentCaseSelection(createdCaseId, { suppressAutoSelect: false });
          renderCasesView();
        }
        if (options.openCaseAfterCreate && createdCaseId) {
          await openCaseWorkspace(createdCaseId);
        }
        dispatchSocAction({
          ...createAction,
          targetId: createdCaseId || frontendAlertId,
          relatedCaseId: createdCaseId,
          result: { caseId: createdCaseId, lifecycle: "in_case" }
        });
        showToast(existingCase ? "Case already exists" : "Case created");
        return;
      }

      if (!config.apiKey) {
        window.alert("Enter API key before creating a case.");
        return;
      }

      const backendAlertId = getBackendAlertId(alert);
      const existingInvestigation = investigationsCache.find(record =>
        String(record?.alert_id || record?.alert?.id || "") === String(backendAlertId)
      );
      const investigationPayload = existingInvestigation
        ? { investigation: existingInvestigation }
        : await requestJson("/investigations", {
          method: "POST",
          body: JSON.stringify({
            alert_id: backendAlertId,
            title: `Investigation for ${alert.attackType}`,
            summary: `Created from alert ${backendAlertId}`
          })
        });
      const casePayload = await requestJson("/cases", {
        method: "POST",
        body: JSON.stringify({
          alert_id: backendAlertId,
          investigation_id: investigationPayload.investigation?.id,
          title: `${alert.attackType} case`,
          priority: alert.severity || "medium",
          summary: `Escalated from ${alert.sourceIp}`,
          timeline: buildCaseCreationTimeline({
            id: backendAlertId,
            attackType: alert.attackType
          }, backendAlertId, actor),
          action: buildActionObject({
            actionType: "create_case",
            actor,
            targetType: "case",
            targetId: backendAlertId,
            relatedAlertId: backendAlertId,
            input: { alertId: backendAlertId },
            result: { lifecycle: "in_case" },
            message: `${actor} created case from alert ${backendAlertId}`
          })
        })
      });
      await loadInvestigations();
      await loadCases();
      const createdCaseId = casePayload.case?.id || null;
      const createdInvestigationId = casePayload.case?.source_investigation_id || investigationPayload.investigation?.id || null;
      markAlertCaseCreatedLocally(frontendAlertId, {
        caseId: createdCaseId,
        investigationId: createdInvestigationId
      });
      if (state.currentView === "investigations") {
        renderInvestigationsView();
      }
      if (state.currentView === "cases" && createdCaseId) {
        setCurrentCaseSelection(createdCaseId, { suppressAutoSelect: false });
        renderCasesView();
      }
      if (options.openCaseAfterCreate && createdCaseId) {
        await openCaseWorkspace(createdCaseId);
      }
      dispatchSocAction({
        ...(parseActionEntry(casePayload.case?.actions?.[0]) || buildActionObject({
          actionType: "create_case",
          actor,
          targetType: "case",
          targetId: createdCaseId || backendAlertId,
          relatedCaseId: createdCaseId,
          relatedAlertId: backendAlertId,
          input: { alertId: backendAlertId },
          result: { caseId: createdCaseId, lifecycle: "in_case" },
          message: `${actor} created case from alert ${backendAlertId}`
        })),
        targetId: createdCaseId || backendAlertId,
        relatedCaseId: createdCaseId,
        relatedAlertId: backendAlertId,
        result: { caseId: createdCaseId, lifecycle: "in_case" }
      });
      showToast(createdCaseId ? "Case created" : "Case already exists");
    } catch (error) {
      console.error(error);
      window.alert(error.message || "Failed to create case");
    } finally {
      endPendingAlertAction(pendingKey);
    }
  }

  window.createCaseFromAlert = async id => {
    await createCaseFromAlertWorkflow(id);
  };

  window.openCaseWorkspace = async (caseId, options = {}) => openCaseWorkspace(caseId, options || {});

  window.openOrCreateCaseForAlert = async alertId => {
    const frontendAlertId = getFrontendAlertId(alertId);
    const alert = findAlertByAnyId(frontendAlertId);
    const linkedCaseId = String(
      alert?.caseId
      || alert?.case_id
      || alert?.mergedIntoCaseId
      || alert?.merged_into_case_id
      || ""
    ).trim();
    const linkedCase = (linkedCaseId
      ? casesCache.find(entry => String(entry?.id || "") === linkedCaseId)
      : null)
      || selectLinkedCaseForAlert(state, frontendAlertId)
      || null;
    if (linkedCase?.id) {
      await openCaseWorkspace(linkedCase.id);
      return;
    }
    await createCaseFromAlertWorkflow(frontendAlertId, { openCaseAfterCreate: true });
  };

  function appendDemoCaseActivity(caseId, entryUpdater, timelineEvents = []) {
    setCasesState(casesCache.map(entry => {
      if (entry.id !== caseId) {
        return entry;
      }
      const nextEntry = entryUpdater(entry);
      return {
        ...nextEntry,
        timeline: appendTimelineToCaseRecord(nextEntry, timelineEvents)
      };
    }));
  }

  function appendCaseActionToDemo(caseId, action, entryUpdater = null, timelineEvents = []) {
    appendDemoCaseActivity(caseId, entry => {
      const nextEntry = entryUpdater ? entryUpdater(entry) : entry;
      const evidence = normalizeCaseEvidence(nextEntry);
      return {
        ...nextEntry,
        updated_at: Date.now() / 1000,
        actions: [...(Array.isArray(nextEntry.actions) ? nextEntry.actions : []), action],
        evidence: {
          timeline: [...evidence.timeline, action],
          enrichments: evidence.enrichments,
          analyst_notes: evidence.analystNotes
        }
      };
    }, timelineEvents);
  }

  async function persistCaseAction(caseId, payload = {}) {
    return requestJson(`/cases/${encodeURIComponent(caseId)}`, {
      method: "POST",
      body: JSON.stringify(payload)
    });
  }

  async function closeCaseWorkflow(caseId, status) {
    if (!caseId || !status) {
      return;
    }
    try {
      requireAuth();
    } catch {
      return;
    }

    const existingCase = casesCache.find(entry => entry.id === caseId);
    if (normalizeCaseStatus(existingCase?.status) === "closed" && status !== "open") {
      return;
    }
    const pendingKey = beginPendingCaseAction("status", caseId);
    if (!pendingKey) {
      return;
    }
    const normalizedStatus = normalizeCaseStatus(status);
    const isTerminalStatus = normalizedStatus === "closed";
    const statusTimestamp = Date.now() / 1000;
    const statusTimelineEvents = buildStatusTimelineEvents(existingCase, normalizedStatus, getCurrentActor(), statusTimestamp);
    const isReopenAction = normalizedStatus === "open";
    const statusLabel = CASE_STATUS_LABELS[normalizedStatus] || normalizedStatus;
    const statusAction = buildCaseAction(
      isReopenAction ? "reopen_case" : (normalizedStatus === "closed" ? "close_case" : "change_case_status"),
      existingCase,
      isReopenAction
        ? `${getCurrentActor()} reopened case ${existingCase?.title || caseId}`
        : normalizedStatus === "closed"
          ? `${getCurrentActor()} closed case ${existingCase?.title || caseId}`
          : `${getCurrentActor()} moved case ${existingCase?.title || caseId} to ${statusLabel}`,
      { status: normalizedStatus },
      { status: normalizedStatus }
    );

    const applySequentialCaseSelection = () => {
      if (isTerminalStatus) {
        applyWorkflowState(workflowCommands.closeCase(state, caseId));
        applyPostClosureCaseSelection(caseId);
        return;
      }
      if (normalizedStatus === "open") {
        selectedCaseTab = "active";
        caseQueueCompletionMessage = "";
        pendingQueuedCaseId = String(caseId);
        setCurrentCaseSelection(caseId, { suppressAutoSelect: false });
        syncCaseQueueState();
      }
    };

    if (state.mode === "demo") {
      appendCaseActionToDemo(caseId, statusAction, entry => ({
        ...entry,
        status: normalizedStatus,
        updated_at: statusTimestamp,
        ...(normalizedStatus === "closed"
          ? { closedAt: statusTimestamp * 1000, closed_at: statusTimestamp * 1000 }
          : { closedAt: null, closed_at: null, closureReason: null, closure_reason: null })
      }), statusTimelineEvents);
      applySequentialCaseSelection();
      renderCasesView();
      dispatchSocAction(statusAction);
      showToast(`Case moved to ${statusLabel}`);
      endPendingCaseAction(pendingKey);
      return;
    }

    try {
      await persistCaseAction(caseId, {
        status: normalizedStatus,
        ...(normalizedStatus === "closed"
          ? { closedAt: statusTimestamp * 1000, closed_at: statusTimestamp * 1000 }
          : { closedAt: null, closed_at: null, closureReason: null, closure_reason: null }),
        action: statusAction,
        timeline: appendTimelineToCaseRecord(existingCase, statusTimelineEvents)
      });
      applySequentialCaseSelection();
      await loadCases();
      await loadInvestigations();
      await loadAuditLogs();
      if (state.currentView === "cases") {
        renderCasesView();
      }
      dispatchSocAction(statusAction);
      showToast(`Case moved to ${statusLabel}`);
    } catch (error) {
      console.error(error);
      window.alert(error.message || "Failed to update case status");
    } finally {
      endPendingCaseAction(pendingKey);
    }
  }

  window.updateCaseStatus = async (caseId, status) => {
    await closeCaseWorkflow(caseId, status);
  };

  window.reopenCase = async caseId => {
    await closeCaseWorkflow(caseId, "open");
  };

  window.submitCaseStatus = async caseId => {
    const statusNode = document.getElementById("case-status-select");
    const nextStatus = String(statusNode?.value || "").trim();
    if (!caseId || !nextStatus) {
      return;
    }
    await window.updateCaseStatus?.(caseId, nextStatus);
  };

  window.updateCasePriority = async (caseId, priority) => {
    if (!caseId || !priority) {
      return;
    }
    const existingCase = casesCache.find(entry => entry.id === caseId);
    if (normalizeCaseStatus(existingCase?.status) === "closed") {
      return;
    }
    try {
      requireAuth();
    } catch {
      return;
    }
    const priorityAction = buildCaseAction(
      "change_priority",
      existingCase,
      `${getCurrentActor()} changed priority to ${String(priority || "medium").toUpperCase()} on case ${existingCase?.title || caseId}`,
      { priority },
      { priority }
    );

    if (state.mode === "demo") {
      appendCaseActionToDemo(caseId, priorityAction, entry => ({ ...entry, priority }));
      renderCasesView();
      dispatchSocAction(priorityAction);
      showToast(`Priority set to ${String(priority).toUpperCase()}`);
      return;
    }

    try {
      await persistCaseAction(caseId, { priority, action: priorityAction });
      await loadCases();
      await loadInvestigations();
      if (state.currentView === "cases") {
        renderCasesView();
      }
      dispatchSocAction(priorityAction);
      showToast(`Priority set to ${String(priority).toUpperCase()}`);
    } catch (error) {
      console.error(error);
      window.alert(error.message || "Failed to update case priority");
    }
  };

  window.handleCaseAssigneeSelectionChange = caseId => {
    const assigneeNode = document.getElementById("case-assignee-input");
    if (!caseId || !assigneeNode) {
      return;
    }
    pendingCaseAssigneeSelections[String(caseId)] = String(assigneeNode.value || "").trim();
    if (state.currentView === "cases") {
      renderCasesView();
    }
  };

  window.assignCaseAssignee = async caseId => {
    const assigneeNode = document.getElementById("case-assignee-input");
    const pendingAssignee = Object.prototype.hasOwnProperty.call(pendingCaseAssigneeSelections, String(caseId))
      ? pendingCaseAssigneeSelections[String(caseId)]
      : String(assigneeNode?.value || "").trim();
    const assignee = String(pendingAssignee || "").trim();
    if (!caseId) {
      return;
    }
    const existingCase = casesCache.find(entry => entry.id === caseId);
    if (normalizeCaseStatus(existingCase?.status) === "closed") {
      return;
    }
    try {
      requireAuth();
    } catch {
      return;
    }
    if (!isAdmin()) {
      return;
    }
    const previousAssignee = String(existingCase?.assignee || "").trim();
    if (assignee === previousAssignee) {
      delete pendingCaseAssigneeSelections[String(caseId)];
      if (state.currentView === "cases") {
        renderCasesView();
      }
      return;
    }
    pendingCaseAssigneeId = String(caseId);
    if (state.currentView === "cases") {
      renderCasesView();
    }
    const assignmentAction = buildCaseAction(
      "assign_case",
      existingCase,
      `${getCurrentActor()} reassigned case ${existingCase?.title || caseId} from ${previousAssignee || "Unassigned"} to ${assignee || "Unassigned"}`,
      { previousAssignee: previousAssignee || null, assignee: assignee || null },
      { assignee: assignee || null }
    );

    if (state.mode === "demo" || !state.apiKey) {
      appendCaseActionToDemo(caseId, assignmentAction, entry => ({ ...entry, assignee: assignee || null }));
      if (!availableCaseAssignees.includes(assignee) && assignee) {
        availableCaseAssignees = [...availableCaseAssignees, assignee].sort((left, right) => String(left).localeCompare(String(right)));
      }
      delete pendingCaseAssigneeSelections[String(caseId)];
      pendingCaseAssigneeId = null;
      renderCasesView();
      dispatchSocAction(assignmentAction);
      showToast(`Assigned to ${assignee || "Unassigned"}`);
      return;
    }

    try {
      const payload = await requestJson(`/cases/${encodeURIComponent(caseId)}/assignee`, {
        method: "PATCH",
        body: JSON.stringify({ assignee })
      });
      updateCaseLocally(caseId, entry => ({ ...entry, ...(payload.case || {}), assignee: payload.case?.assignee || assignee || null }));
      if (!availableCaseAssignees.includes(assignee) && assignee) {
        availableCaseAssignees = [...availableCaseAssignees, assignee].sort((left, right) => String(left).localeCompare(String(right)));
      }
      delete pendingCaseAssigneeSelections[String(caseId)];
      dispatchSocAction(assignmentAction);
      showToast(`Assigned to ${assignee || "Unassigned"}`);
    } catch (error) {
      console.error(error);
      window.alert(error.message || "Failed to assign case");
    } finally {
      pendingCaseAssigneeId = null;
      if (state.currentView === "cases") {
        renderCasesView();
      }
    }
  };

  window.assignCaseAnalyst = window.assignCaseAssignee;

  window.addCaseNote = async caseId => {
    const note = String(document.getElementById("case-note-input")?.value || "").trim();
    if (!caseId || !note) {
      return;
    }
    const existingCase = casesCache.find(entry => entry.id === caseId);
    if (normalizeCaseStatus(existingCase?.status) === "closed") {
      return;
    }
    try {
      requireAuth();
    } catch {
      return;
    }
    const noteAction = buildCaseAction(
      "add_note",
      existingCase,
      `${getCurrentActor()} added a note to case ${existingCase?.title || caseId}`,
      { note },
      { note }
    );
    const encodedNote = encodeActionNote(noteAction);
    const noteTimestamp = Date.now() / 1000;
    const noteTimelineEvents = [
      createCaseTimelineEntry("note_added", { note }, getCurrentActor(), noteTimestamp)
    ];

    if (state.mode === "demo") {
      appendDemoCaseActivity(caseId, entry => ({
        ...entry,
        updated_at: noteTimestamp,
        notes: [...(Array.isArray(entry.notes) ? entry.notes : []), { text: encodedNote, timestamp: noteTimestamp }],
        evidence: {
          timeline: [...normalizeCaseEvidence(entry).timeline, noteAction],
          enrichments: normalizeCaseEvidence(entry).enrichments,
          analyst_notes: [...normalizeCaseEvidence(entry).analystNotes, { text: encodedNote, timestamp: noteTimestamp }]
        }
      }), noteTimelineEvents);
      const noteInput = document.getElementById("case-note-input");
      if (noteInput) {
        noteInput.value = "";
      }
      renderCasesView();
      dispatchSocAction(noteAction);
      showToast("Case note added");
      return;
    }

    try {
      await persistCaseAction(caseId, {
        note: encodedNote,
        action: noteAction,
        timeline: appendTimelineToCaseRecord(existingCase, noteTimelineEvents)
      });
      await loadCases();
      await loadAuditLogs();
      const noteInput = document.getElementById("case-note-input");
      if (noteInput) {
        noteInput.value = "";
      }
      if (state.currentView === "cases") {
        renderCasesView();
      }
      dispatchSocAction(noteAction);
      showToast("Case note added");
    } catch (error) {
      console.error(error);
      window.alert(error.message || "Failed to add case note");
    }
  };

  window.submitCasePriority = caseId => {
    const priority = document.getElementById("case-priority-select")?.value;
    if (caseId && priority) {
      window.updateCasePriority?.(caseId, priority);
    }
  };

  async function markAlertOnlyFalsePositiveWorkflow(alertId) {
    if (!alertId) {
      return;
    }
    if (state.mode !== "demo" && !config.apiKey) {
      window.alert("Enter API key before marking a false positive.");
      return;
    }
    if (state.mode === "demo") {
      applyDemoAlertUpdate(alertEntry => {
        if (buildLocalAlertId(alertEntry) !== String(alertId)) {
          return false;
        }
        Object.assign(alertEntry, applyAlertLifecycle(alertEntry, "false_positive"));
        return true;
      });
    } else {
      await postAlertAction(config.apiBaseUrl, config.apiKey, "/actions/false-positive", { id: getBackendAlertId(alertId) });
    }
    updateAlertLifecycleLocally(alertId, "false_positive");
    applyWorkflowState(workflowCommands.markAlertFalsePositive(state, alertId));
    renderInvestigationsView();
    dispatchSocAction({
      actionType: "mark_false_positive",
      actor: getCurrentActor(),
      targetType: "alert",
      targetId: alertId,
      relatedAlertId: alertId,
      result: { lifecycle: "false_positive", caseStatus: "none" },
      message: `${getCurrentActor()} marked alert ${alertId} as false positive without a linked case`
    });
    showToast("Alert marked false positive without a linked case");
  }

  function applyPostClosureCaseSelection(caseId) {
    const normalizedCaseId = String(caseId || "");
    const wasQueued = selectedCaseQueue.includes(normalizedCaseId);
    const wasSelected = String(selectedCaseId || "") === normalizedCaseId;
    const nextQueuedCaseId = getQueuedNextCaseId(normalizedCaseId);

    selectedCaseQueue = selectedCaseQueue.filter(entry => String(entry) !== normalizedCaseId);
    syncCaseQueueState();
    selectedCaseTab = "active";

    if (wasQueued || wasSelected) {
      if (nextQueuedCaseId) {
        caseQueueCompletionMessage = "";
        pendingQueuedCaseId = String(nextQueuedCaseId);
        setCurrentCaseSelection(nextQueuedCaseId, { suppressAutoSelect: false });
      } else {
        caseQueueCompletionMessage = "All selected cases processed";
        pendingQueuedCaseId = null;
        setCurrentCaseSelection(null, { suppressAutoSelect: true });
      }
      return;
    }

    caseQueueCompletionMessage = "";
    pendingQueuedCaseId = selectedCaseId ? String(selectedCaseId) : null;
  }

  async function markCaseFalsePositiveWorkflow(caseId, { sourceAlertId = null } = {}) {
    const caseRecord = casesCache.find(entry => String(entry.id) === String(caseId));
    const resolvedAlertId = sourceAlertId || caseRecord?.source_alert_id || caseRecord?.alert_id || caseRecord?.alert?.id;
    if (!caseRecord || !resolvedAlertId) {
      showToast("No source alert available");
      return false;
    }
    if (state.mode !== "demo" && !config.apiKey) {
      window.alert("Enter API key before marking a false positive.");
      return false;
    }
    const pendingKey = beginPendingCaseAction("false_positive", caseId);
    if (!pendingKey) {
      return false;
    }
    const closedAt = Date.now();
    const falsePositiveTimelineEvents = buildFalsePositiveTimelineEvents(caseRecord, closedAt);
    const falsePositiveAction = buildCaseAction(
      "mark_false_positive",
      caseRecord,
      `${getCurrentActor()} marked case ${caseRecord.title || caseId} as false positive`,
      { alertId: resolvedAlertId },
      { lifecycle: "false_positive", caseStatus: "closed", closureReason: "false_positive", closedAt }
    );

    try {
      if (state.mode === "demo") {
        appendCaseActionToDemo(caseId, falsePositiveAction, entry => ({
          ...entry,
          status: "closed",
          closureReason: "false_positive",
          closure_reason: "false_positive",
          closedAt,
          closed_at: closedAt,
          updated_at: Date.now() / 1000
        }), falsePositiveTimelineEvents);
        updateAlertLifecycleLocally(resolvedAlertId, "false_positive");
      } else {
        await persistCaseAction(caseId, {
          status: "closed",
          closureReason: "false_positive",
          closure_reason: "false_positive",
          closedAt,
          closed_at: closedAt,
          action: falsePositiveAction,
          timeline: appendTimelineToCaseRecord(caseRecord, falsePositiveTimelineEvents)
        });
        await postAlertAction(config.apiBaseUrl, config.apiKey, "/actions/false-positive", { id: getBackendAlertId(resolvedAlertId) });
        updateAlertLifecycleLocally(resolvedAlertId, "false_positive");
        await loadCases();
        await loadInvestigations();
        await loadAuditLogs();
        if (!casesCache.some(entry => String(entry.id) === String(caseId))) {
          throw new Error("Closed case could not be reloaded");
        }
      }

      applyPostClosureCaseSelection(caseId);
      renderCasesView();
      renderInvestigationsView();
      dispatchSocAction(falsePositiveAction);
      showToast("Case closed as false positive");
      return true;
    } catch (error) {
      console.error(error);
      window.alert(error.message || "Failed to mark alert as false positive");
      return false;
    } finally {
      endPendingCaseAction(pendingKey);
    }
  }

  window.markCaseAlertFalsePositive = async caseId => {
    return markCaseFalsePositiveWorkflow(caseId);
  };

  window.generateCaseReport = caseId => {
    const caseRecord = casesCache.find(entry => entry.id === caseId);
    if (!caseRecord || !window.jspdf?.jsPDF) {
      window.alert("PDF generation is unavailable.");
      return;
    }

    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    const sourceAlert = caseRecord.alert || {};
    const timeline = buildCaseTimeline(caseRecord);
    const linkedAlerts = getCaseLinkedAlerts(caseRecord);
    let y = 16;
    const pushLine = (text, gap = 7) => {
      const lines = doc.splitTextToSize(String(text || ""), 180);
      doc.text(lines, 15, y);
      y += lines.length * 6 + gap;
    };

    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    pushLine(caseRecord.title || "Incident Report", 5);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(11);
    pushLine(`Case ID: ${caseRecord.id}`);
    pushLine(`Status: ${CASE_STATUS_LABELS[String(caseRecord.status || "open").toLowerCase()] || caseRecord.status}`);
    pushLine(`Priority: ${String(caseRecord.priority || "medium").toUpperCase()}`);
    pushLine(`Severity: ${String(caseRecord.severity || sourceAlert.severity || "medium").toUpperCase()}`);
    pushLine(`Assignee: ${caseRecord.assignee || "Unassigned"}`);
    pushLine(`Created: ${formatAbsoluteTime(caseRecord.created_at)}`);
    pushLine(`Updated: ${formatAbsoluteTime(caseRecord.updated_at)}`);
    pushLine("Summary", 3);
    pushLine(caseRecord.summary || "No summary provided.");
    pushLine("Source Context", 3);
    pushLine(`Linked alert: ${caseRecord.source_alert_id || caseRecord.alert_id || "None"}`);
    pushLine(`Linked investigation: ${caseRecord.source_investigation_id || caseRecord.investigation_id || "None"}`);
    pushLine(`Source IP: ${sourceAlert.source_ip || sourceAlert.sourceIp || sourceAlert.ip || "Unknown"}`);
    pushLine(`Attack type: ${sourceAlert.attack_type || sourceAlert.attackType || sourceAlert.rule || "Unknown"}`);
    pushLine("Timeline", 3);
    timeline.forEach(entry => pushLine(`${formatAbsoluteTime(entry.timestamp)} | ${entry.author || "Unknown"} | ${entry.type}: ${entry.label}`, 2));
    pushLine("Linked Alerts", 3);
    linkedAlerts.forEach(alert => pushLine(`${String(alert.severity || "medium").toUpperCase()} | ${alert.attack_type || alert.attackType || alert.rule || alert.id} | ${alert.source_ip || alert.sourceIp || alert.ip || "unknown"}`, 2));
    doc.save(`${caseRecord.id}-incident-report.pdf`);

    const reportAction = buildCaseAction(
      "generate_report",
      caseRecord,
      `${getCurrentActor()} generated a report for case ${caseRecord.title || caseId}`,
      null,
      { report: `${caseRecord.id}-incident-report.pdf` }
    );
    if (state.mode === "demo") {
      appendCaseActionToDemo(caseId, reportAction);
      renderCasesView();
    }
    dispatchSocAction(reportAction);
    showToast("PDF report generated");
  };

  async function downloadCaseExport(caseId, section, format = "json") {
    const caseRecord = casesCache.find(entry => String(entry.id) === String(caseId));
    if (!caseRecord) {
      showToast("Case not found");
      return;
    }

    const filenameBase = `${caseRecord.id}-${section}`;
    if (state.mode === "demo" || !state.apiKey) {
      if (section === "full" && format === "pdf") {
        window.generateCaseReport?.(caseId);
        return;
      }
      const sourceAlert = caseRecord.alert || {};
      const payload = {
        case_id: caseRecord.id,
        overview: {
          title: caseRecord.title,
          status: caseRecord.status,
          priority: caseRecord.priority,
          severity: caseRecord.severity,
          assignee: caseRecord.assignee,
          created_at: caseRecord.created_at,
          updated_at: caseRecord.updated_at
        },
        alerts: getCaseLinkedAlerts(caseRecord).map(alert => ({
          id: alert.id,
          attack_type: alert.attack_type || alert.attackType || alert.rule,
          source_ip: alert.source_ip || alert.sourceIp || alert.ip,
          severity: alert.severity,
          country: alert.country,
          disposition: alert.disposition
        })),
        timeline: buildCaseTimeline(caseRecord),
        evidence: normalizeCaseEvidence(caseRecord),
        conclusion: {
          summary: caseRecord.summary || "No summary provided.",
          primary_source_ip: sourceAlert.source_ip || sourceAlert.sourceIp || sourceAlert.ip || "Unknown"
        }
      };
      if (section === "timeline") {
        downloadJsonFile(`${filenameBase}.json`, {
          case_id: payload.case_id,
          overview: payload.overview,
          timeline: payload.timeline
        });
      } else if (section === "summary") {
        downloadJsonFile(`${filenameBase}.json`, {
          case_id: payload.case_id,
          overview: payload.overview,
          conclusion: payload.conclusion
        });
      } else {
        downloadJsonFile(`${filenameBase}.json`, payload);
      }
      showToast(`Exported ${section}`);
      return;
    }

    try {
      const url = `${normalizeBaseUrl(config.apiBaseUrl)}/cases/${encodeURIComponent(caseId)}/report?section=${encodeURIComponent(section)}&format=${encodeURIComponent(format)}`;
      const response = await apiFetch(url);
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload?.detail || payload?.message || "Failed to export case report");
      }
      const blob = await response.blob();
      downloadBlobFile(blob, `${filenameBase}.${format === "pdf" ? "pdf" : "json"}`);
      if (section === "full") {
        const reportAction = buildCaseAction(
          "generate_report",
          caseRecord,
          `${getCurrentActor()} generated a report for case ${caseRecord.title || caseId}`,
          { section, format },
          { report: `${filenameBase}.${format === "pdf" ? "pdf" : "json"}` }
        );
        dispatchSocAction(reportAction);
      }
      showToast(`Exported ${section}`);
    } catch (error) {
      console.error(error);
      window.alert(error.message || "Failed to export case data");
    }
  }

  window.exportCaseReport = async caseId => {
    await downloadCaseExport(caseId, "full", "pdf");
  };

  window.exportCaseTimeline = async caseId => {
    await downloadCaseExport(caseId, "timeline", "json");
  };

  window.exportCaseSummary = async caseId => {
    await downloadCaseExport(caseId, "summary", "json");
  };

  function openCaseRelationship(caseId) {
    const relatedCaseId = String(caseId || "");
    if (!relatedCaseId) {
      return;
    }
    setCurrentCaseSelection(relatedCaseId, { suppressAutoSelect: false });
    selectedCaseTab = normalizeCaseStatus(casesCache.find(entry => String(entry.id) === relatedCaseId)?.status) === "closed" ? "closed" : "active";
    renderCasesView();
  }

  window.openCaseRelationship = openCaseRelationship;

  function appendRelationshipActionToDemo(caseId, action, entryUpdater = null) {
    appendCaseActionToDemo(caseId, action, entry => {
      const nextEntry = entryUpdater ? entryUpdater(entry) : entry;
      return {
        ...nextEntry,
        parent_case_id: nextEntry.parent_case_id ?? nextEntry.parentCaseId ?? null,
        linked_cases: Array.isArray(nextEntry.linked_cases) ? [...new Set(nextEntry.linked_cases.map(String))] : []
      };
    });
  }

  async function executeCaseRelationship(caseId, operation, providedTarget = null) {
    const caseRecord = casesCache.find(entry => String(entry.id) === String(caseId));
    if (!caseRecord) {
      showToast("Case not found");
      return;
    }
    try {
      requireAuth();
    } catch {
      return;
    }

    if (operation === "link") {
      const linkedCaseId = providedTarget == null
        ? String(window.prompt("Link to case ID:", "") || "").trim()
        : String(providedTarget || "").trim();
      if (!linkedCaseId) {
        return;
      }
      const relationshipAction = buildCaseAction(
        "link_cases",
        caseRecord,
        `${getCurrentActor()} linked case ${caseRecord.id} to case ${linkedCaseId}`,
        { linkedCaseId },
        { linkedCaseId }
      );
      if (state.mode === "demo") {
        appendRelationshipActionToDemo(caseId, relationshipAction, entry => ({
          ...entry,
          linked_cases: [...new Set([...(Array.isArray(entry.linked_cases) ? entry.linked_cases : []), linkedCaseId])]
        }));
        appendRelationshipActionToDemo(linkedCaseId, relationshipAction, entry => ({
          ...entry,
          linked_cases: [...new Set([...(Array.isArray(entry.linked_cases) ? entry.linked_cases : []), caseId])]
        }));
        renderCasesView();
        dispatchSocAction(relationshipAction);
        showToast(`Linked case ${linkedCaseId}`);
        return;
      }
      await requestJson("/cases/link", {
        method: "POST",
        body: JSON.stringify({ case_id: caseId, linked_case_id: linkedCaseId, action: relationshipAction })
      });
      await loadCases();
      await loadAuditLogs();
      renderCasesView();
      dispatchSocAction(relationshipAction);
      showToast(`Linked case ${linkedCaseId}`);
      return;
    }

    if (operation === "merge") {
      const secondaryCaseId = providedTarget == null
        ? String(window.prompt("Merge case ID into this case:", "") || "").trim()
        : String(providedTarget || "").trim();
      if (!secondaryCaseId) {
        return;
      }
      const relationshipAction = buildCaseAction(
        "merge_cases",
        caseRecord,
        `${getCurrentActor()} merged case ${secondaryCaseId} into case ${caseRecord.id}`,
        { mergedCaseId: secondaryCaseId },
        { mergedCaseId: secondaryCaseId }
      );
      if (state.mode === "demo") {
        const secondaryCase = casesCache.find(entry => String(entry.id) === secondaryCaseId);
        appendRelationshipActionToDemo(caseId, relationshipAction, entry => ({
          ...entry,
          linked_alert_ids: [...new Set([...(Array.isArray(entry.linked_alert_ids) ? entry.linked_alert_ids : []), ...((secondaryCase?.linked_alert_ids) || [])])],
          linked_cases: [...new Set([...(Array.isArray(entry.linked_cases) ? entry.linked_cases : []), secondaryCaseId, ...((secondaryCase?.linked_cases) || [])])]
        }));
        appendRelationshipActionToDemo(secondaryCaseId, relationshipAction, entry => ({
          ...entry,
          parent_case_id: caseId,
          linked_cases: [...new Set([...(Array.isArray(entry.linked_cases) ? entry.linked_cases : []), caseId])],
          status: "closed"
        }));
        renderCasesView();
        dispatchSocAction(relationshipAction);
        showToast(`Merged case ${secondaryCaseId}`);
        return;
      }
      await requestJson("/cases/merge", {
        method: "POST",
        body: JSON.stringify({ primary_case_id: caseId, secondary_case_id: secondaryCaseId, action: relationshipAction })
      });
      await loadCases();
      await loadAuditLogs();
      renderCasesView();
      dispatchSocAction(relationshipAction);
      showToast(`Merged case ${secondaryCaseId}`);
      return;
    }

    if (operation === "split") {
      const availableAlerts = getCaseLinkedAlerts(caseRecord).map(alert => String(alert.id || alert.alert_id || "")).filter(Boolean);
      const input = providedTarget == null
        ? String(window.prompt(`Split alerts into a new case.\nAvailable: ${availableAlerts.join(", ")}`, "") || "").trim()
        : (Array.isArray(providedTarget) ? providedTarget.join(",") : String(providedTarget || "").trim());
      if (!input) {
        return;
      }
      const alertIds = input.split(",").map(value => value.trim()).filter(Boolean);
      const relationshipAction = buildCaseAction(
        "split_case",
        caseRecord,
        `${getCurrentActor()} split alerts from case ${caseRecord.id}`,
        { alertIds },
        { alertIds }
      );
      if (state.mode === "demo") {
        const newCaseId = `case-split-${Date.now()}`;
        appendRelationshipActionToDemo(caseId, relationshipAction, entry => ({
          ...entry,
          linked_alert_ids: (Array.isArray(entry.linked_alert_ids) ? entry.linked_alert_ids : []).filter(value => !alertIds.includes(String(value))),
          linked_cases: [...new Set([...(Array.isArray(entry.linked_cases) ? entry.linked_cases : []), newCaseId])]
        }));
        const splitCreatedAt = Date.now() / 1000;
        setCasesState([{
          id: newCaseId,
          title: `${caseRecord.title || "Case"} split`,
          summary: caseRecord.summary || "",
          source_alert_id: alertIds[0] || null,
          alert_id: alertIds[0] || null,
          source_investigation_id: caseRecord.source_investigation_id || caseRecord.investigation_id || null,
          investigation_id: caseRecord.source_investigation_id || caseRecord.investigation_id || null,
          priority: caseRecord.priority || "medium",
          severity: caseRecord.severity || "medium",
          status: "open",
          assignee: caseRecord.assignee || null,
          linked_alert_ids: alertIds,
          linked_cases: [caseId],
          parent_case_id: caseId,
          notes: [],
          actions: [relationshipAction],
          timeline: buildCaseCreationTimeline({ id: alertIds[0] || null }, newCaseId, getCurrentActor(), splitCreatedAt),
          evidence: {
            timeline: [relationshipAction],
            enrichments: normalizeCaseEvidence(caseRecord).enrichments,
            analyst_notes: []
          },
          created_at: splitCreatedAt,
          updated_at: splitCreatedAt
        }, ...casesCache]);
        renderCasesView();
        dispatchSocAction(relationshipAction);
        showToast(`Split ${alertIds.length} alert${alertIds.length === 1 ? "" : "s"} into a new case`);
        return;
      }
      await requestJson("/cases/split", {
        method: "POST",
        body: JSON.stringify({ case_id: caseId, alert_ids: alertIds, action: relationshipAction })
      });
      await loadCases();
      await loadAuditLogs();
      renderCasesView();
      dispatchSocAction(relationshipAction);
      showToast(`Split ${alertIds.length} alert${alertIds.length === 1 ? "" : "s"} into a new case`);
    }
  }

  window.mergeCases = async caseId => {
    await executeCaseRelationship(caseId, "merge");
  };

  window.linkCases = async caseId => {
    await executeCaseRelationship(caseId, "link");
  };

  window.splitCaseAlerts = async caseId => {
    await executeCaseRelationship(caseId, "split");
  };

  window.runCaseBulkAction = async action => {
    const selectedIds = [...new Set(selectedCaseQueue.map(String))];
    if (!selectedIds.length && action !== "clear") {
      showToast("Select one or more cases first");
      return;
    }
    if (action === "clear") {
      selectedCaseQueue = [];
      syncCaseQueueState();
      renderCasesView();
      return;
    }
    if (action === "assign") {
      const suggestedAssignee = state.user?.username || currentUser?.username || "";
      const response = window.prompt("Assign selected cases to analyst:", suggestedAssignee);
      if (response === null) {
        return;
      }
      const assignee = String(response || "").trim();
      for (const caseId of selectedIds) {
        pendingCaseAssigneeSelections[String(caseId)] = assignee;
        await window.assignCaseAssignee?.(caseId);
      }
      showToast(`Updated assignment for ${selectedIds.length} case${selectedIds.length === 1 ? "" : "s"}`);
      return;
    }
    if (action === "close") {
      for (const caseId of selectedIds) {
        await window.updateCaseStatus?.(caseId, "closed");
      }
      showToast(`Closed ${selectedIds.length} case${selectedIds.length === 1 ? "" : "s"}`);
      return;
    }
    if (action === "false-positive") {
      let processedCount = 0;
      for (const caseId of selectedIds) {
        const result = await window.markCaseAlertFalsePositive?.(caseId);
        if (result !== false) {
          processedCount += 1;
        }
      }
      showToast(`Marked ${processedCount} case${processedCount === 1 ? "" : "s"} as false positive`);
      return;
    }
    if (action === "merge") {
      if (selectedIds.length < 2) {
        showToast("Select at least two cases to merge");
        return;
      }
      const [primaryCaseId, ...secondaryCaseIds] = selectedIds;
      for (const secondaryCaseId of secondaryCaseIds) {
        await executeCaseRelationship(primaryCaseId, "merge", secondaryCaseId);
      }
      selectedCaseQueue = [primaryCaseId];
      syncCaseQueueState();
      renderCasesView();
      return;
    }
    if (action === "link") {
      if (selectedIds.length < 2) {
        showToast("Select at least two cases to link");
        return;
      }
      const [primaryCaseId, ...linkedCaseIds] = selectedIds;
      for (const linkedCaseId of linkedCaseIds) {
        await executeCaseRelationship(primaryCaseId, "link", linkedCaseId);
      }
      renderCasesView();
    }
  };

  function stopRefresh() {
    if (refreshInterval) {
      clearInterval(refreshInterval);
      refreshInterval = null;
    }
    setRefreshCountdown("Monitoring paused");
  }

  function applyAlerts(alerts) {
    if (isDemoMode && alerts !== currentDemoAlerts) {
      return;
    }
    const normalizedAlerts = Array.isArray(alerts) ? alerts.map(normalizeAlertModel) : [];
    statsPanel.setAlerts(normalizedAlerts);
    state.alerts = Array.isArray(normalizedAlerts) ? [...normalizedAlerts] : [];
    syncFilteredAlertsState();
    setLastUpdated(normalizedAlerts[0]?.timestamp || Date.now());
    if (state.currentView === "hunt" && currentHuntQuery) {
      currentHuntPayload = buildHuntLocalPayload(currentHuntQuery, currentHuntTimeRange);
      huntResults = currentHuntPayload.alerts;
      renderHuntView();
    }
  }

  async function loadSnapshot(reason = "manual") {
    console.log("LOADSNAPSHOT_CALLED", reason);
    if (state.mode === "demo") {
      return false;
    }

    if (!state.apiKey) {
      statsPanel.reset();
      apiHintNode.textContent = "Set the API key to load alerts and enable live streaming.";
      statsPanel.setConnectionStatus({ label: "API KEY REQUIRED", tone: "error" });
      setRefreshStatus("Enter API key to start monitoring", "Monitoring is paused until access is configured.", "waiting");
      setRefreshCountdown("Monitoring paused");
      setRefreshButtonState(false);
      return false;
    }

    setRefreshButtonState(false);
    apiHintNode.textContent = "Loading alerts from the API.";
    statsPanel.setConnectionStatus({ label: "LOADING", tone: "live" });
    setRefreshStatus(
      reason === "auto" ? "Refreshing live data" : "Refreshing now",
      "Fetching the latest alerts for the dashboard.",
      "waiting"
    );

    const alerts = await fetchAlertSnapshot(config.apiBaseUrl, config.apiKey, currentUser?.username);
    if (isDemoMode) {
      return false;
    }
    applyAlerts(alerts);
    await loadInvestigations();
    await loadCases();
    await loadWatchlist();
    await loadPlaybooks();
    await loadAuditLogs();
    if (isDemoMode) {
      return false;
    }

    apiHintNode.textContent = `Loaded ${alerts.length} alerts.`;
    statsPanel.setConnectionStatus({ label: "CONNECTED", tone: "live" });
    setRefreshStatus("Live monitoring active", "Live updates every 15 seconds.", "connected");
    resetCountdown();
    setRefreshButtonState(true);
    return true;
  }

  function startRefresh() {
    if (refreshInterval) {
      return;
    }

    if (isDemoMode) {
      setRefreshCountdown("Demo mode (static data)");
      setRefreshButtonState(false);
      return;
    }

    resetCountdown();
    setRefreshButtonState(true);
    refreshInterval = setInterval(() => {
      if (isDemoMode) {
        setRefreshCountdown("Demo mode (static data)");
        setRefreshButtonState(false);
        return;
      }

      if (!config.apiKey) {
        setRefreshCountdown("Monitoring paused");
        setRefreshButtonState(false);
        return;
      }

      if (isSnapshotRefreshing) {
        return;
      }

      countdownSeconds = Math.max(0, countdownSeconds - 1);
      setRefreshCountdown(`Next update in ${countdownSeconds}s`);

      if (countdownSeconds === 0) {
        isSnapshotRefreshing = true;
        loadSnapshot("auto").catch(error => {
          statsPanel.setConnectionStatus({ label: "API ERROR", tone: "error" });
          apiHintNode.textContent = error.message;
          setRefreshStatus("Connection lost - retrying...", "Trying again on the next refresh cycle.", "error");
          resetCountdown();
          setRefreshButtonState(true);
        }).finally(() => {
          isSnapshotRefreshing = false;
        });
      }
    }, 1000);
  }

  function stopLiveStream() {
    if (liveStream) {
      liveStream.close();
      liveStream = null;
    }
    setLiveStatus("Offline");
  }

  async function startLiveStream() {
    if (state.mode === "demo") {
      return;
    }

    stopLiveStream();
    setLiveStatus("Connecting");

      liveStream = createLiveStream({
        apiBaseUrl: config.apiBaseUrl,
        apiKey: config.apiKey,
        username: currentUser?.username,
        onEvent(event) {
        if (isDemoMode) {
          return;
        }
          if (event?.type === "alert_update") {
            statsPanel.updateAlertOwnership?.(event);
            apiHintNode.textContent = `Ownership updated for alert ${event.alert_id}.`;
            renderAdminSocView();
            return;
          }
          if (event?.type === "investigating") {
            activeInvestigations.set(String(event.alert_id), {
              alertId: String(event.alert_id),
              user: event.user || event.locked_by || "Unknown",
              timestamp: Date.now()
            });
            statsPanel.updateAlertOwnership?.({
              alert_id: event.alert_id,
              locked_by: event.locked_by || event.user
            });
            renderAdminSocView();
            return;
          }
          statsPanel.recordEvent(event);
          state.alerts = Array.isArray(statsPanel.getAlerts?.()) ? statsPanel.getAlerts() : state.alerts;
          syncFilteredAlertsState();
          if (currentView === "investigations") {
            renderInvestigationsView();
            highlightNewAlert(buildLocalAlertId(event));
          }
        statsPanel.setConnectionStatus({ label: "LIVE", tone: "live" });
        setLiveStatus("Streaming");
        setLastUpdated(event.timestamp);
          apiHintNode.textContent = `Live alert received from ${event.sourceIp}.`;
          setRefreshStatus("Live monitoring active", "Live updates every 15 seconds.", "connected");
          setRefreshButtonState(Boolean(config.apiKey));
          renderAdminSocView();
          loadAuditLogs().catch(error => {
            console.error(error);
          });
      },
      onStatus(status) {
        if (isDemoMode) {
          return;
        }
        statsPanel.setConnectionStatus(status);
        setLiveStatus(status.label);
        if (status.tone === "error") {
          setRefreshStatus("Connection lost - retrying...", "Live updates will resume automatically.", "error");
          setRefreshButtonState(Boolean(config.apiKey));
          return;
        }
        setRefreshStatus("Live monitoring active", "Live updates every 15 seconds.", "connected");
        setRefreshButtonState(Boolean(config.apiKey));
      },
      onError(error) {
        if (isDemoMode) {
          return;
        }
        apiHintNode.textContent = error.message;
        if (config.apiKey) {
          setRefreshStatus("Connection lost - retrying...", "Live updates will resume automatically.", "error");
          setRefreshButtonState(true);
        }
      }
    });

      try {
        await liveStream.connect();
        setLiveStatus("Streaming");
        startSocLiveView();
      } catch (error) {
        stopLiveStream();
      apiHintNode.textContent = error.message;
      if (config.apiKey) {
        setRefreshStatus("Connection lost - retrying...", "Live monitoring will continue retrying.", "error");
      }
    }
  }

  async function refreshDashboard() {
    if (state.mode === "demo") {
      return;
    }

    stopRefresh();
    stopLiveStream();
    stopSocLiveView();

    try {
      await checkApiHealth();
      const shouldConnect = await loadSnapshot();
      if (isDemoMode) {
        return;
      }
      if (!shouldConnect) {
        return;
      }
      startRefresh();
      await startLiveStream();
      startSocLiveView();
    } catch (error) {
      statsPanel.reset();
      statsPanel.setConnectionStatus({ label: "API ERROR", tone: "error" });
      apiHintNode.textContent = error.message;
      setRefreshStatus("Connection lost - retrying...", "We could not load new alerts. Try refreshing again.", "error");
      resetCountdown();
      setRefreshButtonState(Boolean(config.apiKey));
      setLiveStatus("Offline");
      stopSocLiveView();
      console.error(error);
    }
  }

  function enableDemoMode() {
    suppressCaseAutoNavigation = true;
    isDemoMode = true;
    state.mode = "demo";
    currentView = "dashboard";
    state.currentView = "dashboard";
    setCurrentView("dashboard");
    state.selectedAlertId = null;
    state.currentInvestigation = null;
    setSelectedAlertId(null);
    setSelectedEntityKey("");
    selectedCaseId = null;
    selectedCaseQueue = [];
    selectedCaseTab = "active";
    selectedCaseWorkspaceTab = "overview";
    suppressCaseAutoSelect = true;
    caseQueueCompletionMessage = "";
    pendingQueuedCaseId = null;
    pendingDeepLinkCaseId = "";
    missingCaseToastId = "";
    setSelectedCaseId(null);
    syncCaseDeepLink(null, { replace: true });
    syncCaseQueueState();
    activeInvestigations = new Map();
    updateUI();
    demoAuditLogs = [];
    demoReferenceTime = Date.now();
    autoExecutedDemoPlaybooks = new Set();
    currentDemoAlerts = buildStaticDemoAlerts();
    stopRefresh();
    stopLiveStream();
    stopSocLiveView();
    statsPanel.reset();
    statsPanel.setNowProvider(() => demoReferenceTime || Date.now());
    applyAlerts(currentDemoAlerts);
    setLastUpdated(currentDemoAlerts[0]?.timestamp || demoReferenceTime);
    statsPanel.setConnectionStatus({ label: "DEMO MODE", tone: "live" });
    setLiveStatus("Demo Mode (static data)");
    setRefreshStatus("Demo Mode (static data)", "Live refresh is paused while demo data is shown.", "waiting");
    setRefreshCountdown("Demo mode (static data)");
    setRefreshButtonState(false);
    apiHintNode.textContent = "Showing built-in example alerts from multiple countries.";
    statsPanel.setAuditLogs([]);
    loadAssignableUsers();
    loadPlaybooks().catch(() => {});
    const storedDemoCases = loadStoredDemoCases();
    setCasesState(storedDemoCases);
    autoRunDemoPlaybooks().catch(error => {
      console.error(error);
    });
    suppressCaseAutoNavigation = false;
    showView("dashboard");
  }

  window.showDemo = () => {
    if (!requireAuthenticatedUi()) {
      return;
    }
    enableDemoMode();
  };

  window.reload = () => {
    window.location.reload();
  };

  window.runScenario = (name) => {
    if (!isDemoMode) {
      showToast("Simulation only available in demo mode");
      return;
    }

    const data = scenarios[name]("8.8.8.8");
    showToast(`Running ${name.replace("_", " ")} simulation`);

    data.forEach((event, i) => {
      setTimeout(() => {
        statsPanel.recordEvent(event);
        state.alerts = Array.isArray(statsPanel.getAlerts?.()) ? statsPanel.getAlerts() : state.alerts;
        syncFilteredAlertsState();
        // Refresh the current view if it's dashboard or investigations
        if (state.currentView === "dashboard") {
          renderDashboardView();
        } else if (state.currentView === "investigations") {
          renderInvestigationsView();
        }
        highlightNewAlert(event.id);
      }, i * 200);
    });
  };

  window.login = async () => {
    const username = usernameNode?.value.trim() || "";
    const password = passwordNode?.value || "";

    try {
      setLoginError("");
      const user = await loginUser(username, password);
      loginSuccess({
        ...user,
        assignableUsers: Array.isArray(user.assignable_users) ? user.assignable_users : [],
        expiresAt: Date.now() + SESSION_DURATION
      }, user.apiKey || config.apiKey);

      currentUser = state.user;
      isEditingApiKey = false;
      setInputValue(usernameNode, state.user.username);
      updateUserUi();
      state.mode = "live";
      updateUI();
      startSocLiveView();
      syncApiKeyField();
      await loadAssignableUsers();
      await loadPlaybooks();
      await loadDetectionRules();
      showView("dashboard");
      showToast(`Logged in as ${state.user.username}`);
      await refreshDashboard();
      await loadOnlineUsers().catch(() => {});
    } catch (error) {
      console.error(error);
      setLoginError("Invalid username or password");
      passwordNode?.focus();
      showToast(error.message || "Login failed");
    }
  };

  window.logout = async (isSessionTimeout = false) => {
    const username = state.user?.username || currentUser?.username || "Unknown";
    const logoutHeadersReady = Boolean(state.user?.username && state.apiKey && state.mode !== "demo");
    if (logoutHeadersReady) {
      try {
        await fetch(`${config.apiBaseUrl.replace(/\/+$/, "")}/auth/logout`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-API-Key": state.apiKey,
            "X-User": state.user.username
          },
          body: JSON.stringify({
            reason: isSessionTimeout ? "session_expired" : "logout"
          })
        });
      } catch (error) {
        console.error(error);
      }
    }
    authLogout();
    closeIocPivot();
    currentUser = null;
    pendingDeepLinkCaseId = "";
    setCasesState([]);
    setInvestigationsState([]);
    detectionRules = [];
    selectedDetectionRuleKey = "";
    selectedCaseId = null;
    selectedCaseQueue = [];
    suppressCaseAutoSelect = false;
    pendingQueuedCaseId = null;
    availableCaseAssignees = [];
    playbookDefinitions = [];
    playbookExecutions = [];
    casePlaybookUiState = {};
    pendingCaseAssigneeId = null;
    openExportMenuCaseId = null;
    openCaseMoreActionsId = null;
    syncCaseQueueState();
    isEditingApiKey = false;
    setSelectedCaseId(null);
    setInputValue(usernameNode, "");
    setInputValue(passwordNode, "");
    stopSocLiveView();
    updateUserUi();
    showToast(isSessionTimeout ? "Session expired. Please login again." : "Logged out");
    syncSearchVisibility("dashboard");
    syncCaseDeepLink(null, { replace: true });
    localStorage.removeItem(DEMO_CASES_STORAGE_KEY);
  };

  editApiKeyButton?.addEventListener("click", () => {
    if (!isAuthenticated()) {
      return;
    }
    const hasSavedKey = Boolean(config.apiKey || state.apiKey);
    if (hasSavedKey) {
      isEditingApiKey = !isEditingApiKey;
    } else {
      isEditingApiKey = true;
    }
    if (isEditingApiKey) {
      apiKeyInput.value = "";
      apiKeyInput.focus();
    }
    syncApiKeyField();
  });

  saveKeyButton?.addEventListener("click", () => {
    if (!isAuthenticated()) {
      return;
    }
    const nextBaseUrl = normalizeBaseUrl(apiBaseUrlInput?.value || config.apiBaseUrl);
    const nextKey = (isEditingApiKey || !config.apiKey)
      ? (apiKeyInput?.value.trim() || config.apiKey || "")
      : (config.apiKey || "");
    localStorage.setItem("cybermap.apiBaseUrl", nextBaseUrl);
    localStorage.setItem("cybermap.apiKey", nextKey);
    config = { ...config, apiBaseUrl: nextBaseUrl, apiKey: nextKey };
    state.apiKey = nextKey;
    isEditingApiKey = false;
    if (nextKey) {
      state.mode = "live";
      isDemoMode = false;
      updateUI();
    }
    if (endpointNode) {
      endpointNode.textContent = nextBaseUrl;
    }
    syncApiKeyField();
    loadAssignableUsers();
    refreshDashboard();
  });

  reloadButton?.addEventListener("click", () => {
    if (isDemoMode) {
      isDemoMode = false;
      window.location.reload();
      return;
    }
    config = {
      ...config,
      apiBaseUrl: normalizeBaseUrl(apiBaseUrlInput?.value || config.apiBaseUrl),
      apiKey: apiKeyInput?.value.trim() || config.apiKey
    };
    if (config.apiKey) {
      state.mode = "live";
      isDemoMode = false;
      updateUI();
    }
    refreshDashboard();
  });

  refreshNowButton?.addEventListener("click", async () => {
    if (isDemoMode || !config.apiKey || isSnapshotRefreshing) {
      return;
    }

    isSnapshotRefreshing = true;
    try {
      await loadSnapshot("manual");
    } catch (error) {
      statsPanel.setConnectionStatus({ label: "API ERROR", tone: "error" });
      apiHintNode.textContent = error.message;
      setRefreshStatus("Connection lost - retrying...", "We could not load new alerts. Try again shortly.", "error");
    } finally {
      isSnapshotRefreshing = false;
      if (config.apiKey) {
        resetCountdown();
        setRefreshButtonState(true);
      }
    }
  });

  showDemoButton?.addEventListener("click", () => {
    window.showDemo?.();
  });

  downloadReportButton?.addEventListener("click", () => {
    const snapshot = statsPanel.getSnapshot();
    const report = {
      generatedAt: new Date().toISOString(),
      classification: reportClassificationNode?.value || "true_positive",
      notes: reportNotesNode?.value.trim() || "",
      source: {
        apiBaseUrl: config.apiBaseUrl,
        liveStatus: liveStatusNode?.textContent || "Unknown",
        connectionStatus: document.getElementById("connection-status")?.textContent || "Unknown"
      },
      summary: snapshot
    };

    downloadReportFile(report);
    setReportStatus("Downloaded");
  });

  apiKeyInput?.addEventListener("keydown", event => {
    if (event.key === "Enter") {
      event.preventDefault();
      saveKeyButton?.click();
    }
  });

  apiBaseUrlInput?.addEventListener("keydown", event => {
    if (event.key === "Enter") {
      event.preventDefault();
      saveKeyButton?.click();
    }
  });

  globalSearchNode?.addEventListener("input", event => {
    executeSearch(event.target.value).catch(error => {
      console.error(error);
    });
  });

  globalSearchNode?.addEventListener("keydown", event => {
    if (event.key !== "Enter") {
      return;
    }
    event.preventDefault();
    const query = String(event.target?.value || "").trim();
    if (!query) {
      return;
    }
    runHuntQuery(query, currentHuntTimeRange).catch(error => {
      console.error(error);
    });
  });

  huntRunButton?.addEventListener("click", () => {
    runHuntQuery(huntQueryInputNode?.value || "", huntTimeRangeNode?.value || currentHuntTimeRange, { forceView: false }).catch(error => {
      console.error(error);
    });
  });

  huntQueryInputNode?.addEventListener("keydown", event => {
    if (event.key !== "Enter") {
      return;
    }
    event.preventDefault();
    runHuntQuery(huntQueryInputNode?.value || "", huntTimeRangeNode?.value || currentHuntTimeRange, { forceView: false }).catch(error => {
      console.error(error);
    });
  });

  huntTimeRangeNode?.addEventListener("change", () => {
    currentHuntTimeRange = String(huntTimeRangeNode?.value || "24h");
    if (currentHuntQuery) {
      runHuntQuery(currentHuntQuery, currentHuntTimeRange, { forceView: false }).catch(error => {
        console.error(error);
      });
    }
  });

  huntSortNode?.addEventListener("change", () => {
    currentHuntSort = String(huntSortNode?.value || "time_desc");
    renderHuntView();
  });

  huntCaseStatusNode?.addEventListener("change", () => {
    currentHuntCaseStatusFilter = String(huntCaseStatusNode?.value || "all");
    refreshCurrentHuntResults();
  });

  huntAttackFilterNode?.addEventListener("input", () => {
    currentHuntAttackFilter = String(huntAttackFilterNode?.value || "");
    refreshCurrentHuntResults();
  });

  huntStatusFilterNode?.addEventListener("change", () => {
    currentHuntAlertStatusFilter = String(huntStatusFilterNode?.value || "all");
    refreshCurrentHuntResults();
  });

  huntUserFilterNode?.addEventListener("input", () => {
    currentHuntUserFilter = String(huntUserFilterNode?.value || "");
    refreshCurrentHuntResults();
  });

  huntMinRiskNode?.addEventListener("input", () => {
    currentHuntMinRiskFilter = String(huntMinRiskNode?.value || "");
    refreshCurrentHuntResults();
  });

  [caseFilterStatusNode, caseFilterPriorityNode, caseSortNode].forEach(node => {
    node?.addEventListener("change", () => {
      renderCasesView();
    });
  });

  caseTabActiveNode?.addEventListener("click", () => {
    selectedCaseTab = "active";
    renderCasesView();
  });

  caseTabClosedNode?.addEventListener("click", () => {
    selectedCaseTab = "closed";
    renderCasesView();
  });

  [activityFilterActionNode, activityFilterTargetNode].forEach(node => {
    node?.addEventListener("change", () => {
      renderActivityView();
    });
  });

  activityFilterUserNode?.addEventListener("input", () => {
    renderActivityView();
  });

  loginButton?.addEventListener("click", () => {
    window.login?.();
  });

  logoutButton?.addEventListener("click", () => {
    window.logout?.();
  });

  passwordNode?.addEventListener("keydown", event => {
    if (event.key === "Enter") {
      event.preventDefault();
      window.login?.();
    }
  });

  usernameNode?.addEventListener("input", () => {
    if (loginErrorMessage) {
      setLoginError("");
    }
  });

  passwordNode?.addEventListener("input", () => {
    if (loginErrorMessage) {
      setLoginError("");
    }
  });

  passwordToggleNode?.addEventListener("click", () => {
    if (!passwordNode) {
      return;
    }
    const isVisible = passwordNode.type === "text";
    passwordNode.type = isVisible ? "password" : "text";
    passwordToggleNode.setAttribute("aria-label", isVisible ? "Show password" : "Hide password");
    passwordToggleNode.setAttribute("aria-pressed", String(!isVisible));
    passwordToggleNode.querySelector(".password-toggle-show")?.toggleAttribute("hidden", !isVisible);
    passwordToggleNode.querySelector(".password-toggle-hide")?.toggleAttribute("hidden", isVisible);
  });

  document.addEventListener("click", event => {
    if (!openExportMenuCaseId && !openCaseMoreActionsId) {
      return;
    }
    const target = event.target;
    if (target instanceof HTMLElement && (target.closest(".case-export-menu") || target.closest(".case-more-actions"))) {
      return;
    }
    openExportMenuCaseId = null;
    openCaseMoreActionsId = null;
    if (state.currentView === "cases") {
      renderCasesView();
    }
  });

  document.addEventListener("keydown", event => {
    if (!requireAuthenticatedUi() || state.currentView !== "investigations") {
      return;
    }
    if (event.defaultPrevented || event.altKey || event.ctrlKey || event.metaKey) {
      return;
    }
    if (isEditableShortcutTarget(event.target)) {
      return;
    }

    const key = String(event.key || "").toLowerCase();
    if (key === "j") {
      event.preventDefault();
      moveInvestigationsSelection(1);
      return;
    }
    if (key === "k") {
      event.preventDefault();
      moveInvestigationsSelection(-1);
      return;
    }
    if (key === "c") {
      event.preventDefault();
      runInvestigationsShortcut("create-case").catch(error => {
        console.error(error);
      });
      return;
    }
    if (key === "f") {
      event.preventDefault();
      runInvestigationsShortcut("false-positive").catch(error => {
        console.error(error);
      });
    }
  });

  window.addEventListener("popstate", () => {
    pendingDeepLinkCaseId = getCaseIdFromUrl();
    if (!isAuthenticated()) {
      return;
    }
    if (pendingDeepLinkCaseId) {
      applyPendingCaseDeepLink({ notifyIfMissing: true });
      return;
    }
    if (state.currentView === "cases") {
      setCurrentCaseSelection(null, { suppressAutoSelect: true, preserveWorkspaceTab: true });
      renderCasesView();
    }
  });

  updateUserUi();

  if (endpointNode) endpointNode.textContent = config.apiBaseUrl;
  setInputValue(apiBaseUrlInput, config.apiBaseUrl);
  setInputValue(usernameNode, currentUser?.username || "");
  syncApiKeyField();

  window.setInterval(() => {
    if (state.user && Date.now() > Number(state.user.expiresAt || 0)) {
      window.logout?.(true);
    }
  }, 10000);

  if (!isAuthenticated()) {
    stopSocLiveView();
    syncAuthGateUi();
    syncSearchVisibility("dashboard");
    syncShellControlsVisibility("dashboard");
    console.log("BOOTSTRAP COMPLETE");
    return;
  }

  showView("dashboard");
  startSocLiveView();
  state.mode = config.apiKey ? "live" : "demo";
  isDemoMode = !config.apiKey;
  updateUI();
  await loadAssignableUsers();
  if (config.apiKey) {
    await refreshDashboard();
  } else {
    enableDemoMode();
  }

  console.log("BOOTSTRAP COMPLETE");
}

bootstrap().catch(error => {
  const node = document.getElementById("connection-status");
  if (node) {
    node.textContent = "BOOT ERROR";
    node.className = "status-value is-error";
    node.title = error.message;
  }
  const liveStatusNode = document.getElementById("live-status");
  if (liveStatusNode) {
    liveStatusNode.textContent = "Boot error";
  }
  console.error(error);
});
