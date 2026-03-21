import { state } from "../core/state.js";

export function renderCases() {
  const el = document.getElementById("view-cases");
  if (!el) return;

  const cases = state.alerts.filter(a => a.case || a.status === "Escalated");

  if (cases.length === 0) {
    el.innerHTML = "<div class='empty-state'>No open cases</div>";
    return;
  }

  el.innerHTML = `
    <div class="panel">
      <h2>Active Security Cases</h2>
      <div class="cases-list">
        ${cases.map(c => `
          <div class="alert-card ${c.severity?.toLowerCase() || 'medium'}" onclick="window.viewCaseDetails('${c.id}')">
            <div class="case-info">
              <div class="label">ID: ${c.id.substring(0, 8)}</div>
              <div class="value">${c.attackType}</div>
            </div>
            <div class="case-meta" style="text-align: right;">
              <div class="label">${c.assigned_to || "Unassigned"}</div>
              <div class="badge ${c.status === 'Closed' ? 'closed' : 'open'}">${c.status}</div>
            </div>
          </div>
        `).join("")}
      </div>
    </div>
    <div class="panel">
      <h2>Case Timeline</h2>
      <div class="label">Select a case to view audit log and analyst notes.</div>
    </div>
  `;
}
