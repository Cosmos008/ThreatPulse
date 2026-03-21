import { state } from "../core/state.js";

export function renderInvestigations() {
  const el = document.getElementById("view-investigations");
  if (!el) return;

  const alert = state.alerts.find(a => a.id === state.selectedAlertId);

  if (!alert) {
    el.innerHTML = "<div class='empty-state'>No alert selected for investigation</div>";
    return;
  }

  el.innerHTML = `
    <div class="panel">
      <h2>Investigation: ${alert.attackType}</h2>
      <div class="investigation-details">
        <div class="details-grid" style="display: grid; grid-template-columns: 1fr; gap: 8px; margin-bottom: 16px;">
          <div><span class="label">ID:</span> <span class="value">${alert.id.substring(0, 8)}</span></div>
          <div><span class="label">IP:</span> <span class="value">${alert.sourceIp}</span></div>
          <div><span class="label">Severity:</span> <span class="badge ${alert.severity.toLowerCase()}">${alert.severity}</span></div>
          <div><span class="label">Status:</span> <span class="badge ${alert.status === 'Closed' ? 'closed' : 'open'}">${alert.status}</span></div>
        </div>

        <div id="actions" style="display: flex; flex-direction: column; gap: 8px;">
          <button class="nav-item active" onclick="window.blockIp('${alert.sourceIp}')">Block IP</button>
          <button class="nav-item" style="background: rgba(255,255,255,0.1);" onclick="window.escalateAlert('${alert.id}')">Escalate to Case</button>
        </div>
      </div>
    </div>
    <div class="panel">
      <h2>Activity Timeline</h2>
      <div id="timeline">
        <div class="label">Collecting evidence and correlating logs...</div>
        <div class="label" style="margin-top: 10px;">- Event detected: ${alert.attackType}</div>
        <div class="label">- Source: ${alert.sourceIp}</div>
        <div class="label">- Priority: ${alert.severity}</div>
      </div>
    </div>
  `;
}
