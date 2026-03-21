import { state } from "../core/state.js";

export function renderAlerts() {
  const el = document.getElementById("view-alerts");
  if (!el) return;

  if (state.alerts.length === 0) {
    el.innerHTML = "<div class='empty-state'>No active alerts</div>";
    return;
  }

  el.innerHTML = `
    <div class="panel">
      <h2>Active Security Alerts</h2>
      <div class="alerts-list">
        ${state.alerts.map(a => `
          <div class="alert-card ${a.severity.toLowerCase()}" data-id="${a.id}" onclick="window.openInvestigation('${a.id}')">
            <div class="alert-info">
              <div class="label">${a.timestamp || 'JUST NOW'}</div>
              <div class="value">${a.attackType}</div>
            </div>
            <div class="alert-meta" style="text-align: right;">
              <div class="label">${a.sourceIp}</div>
              <div class="badge ${a.status === 'Closed' ? 'closed' : 'open'}">${a.status}</div>
            </div>
          </div>
        `).join("")}
      </div>
    </div>
    <div class="panel">
      <h2>Alert Context</h2>
      <div class="label">Select an alert to view payload and correlation details.</div>
    </div>
  `;
}
