import { state } from "../core/state.js";

export function renderAdmin() {
  const el = document.getElementById("view-admin");
  if (!el) return;

  if (state.user?.role !== "admin") {
    el.innerHTML = "<div class='error-state'>Unauthorized: Admin access required</div>";
    return;
  }

  el.innerHTML = `
    <div class="panel">
      <h2>SOC Management & Presence</h2>
      <div class="admin-list" style="margin-bottom: 12px;">
        <div class="label">Detection Rules</div>
        <div class="value">Active rules: 24</div>
        <button class="nav-item active" style="margin-top: 8px; width: 100%;" onclick="window.renderRules()">Manage Rules</button>
      </div>
    </div>
    <div class="panel">
      <h2>Live SOC Monitor</h2>
      <div class="admin-grid" style="display: grid; grid-template-columns: 1fr; gap: 12px;">
        <div class="admin-section">
          <h3>Presence</h3>
          <div id="admin-presence-list" class="admin-list">
            <div class="label">Monitoring analyst activity...</div>
          </div>
        </div>
        <div class="admin-section">
          <h3>SLA Monitor</h3>
          <div id="admin-sla-monitor" class="admin-list">
            <div class="label">Tracking response times...</div>
          </div>
        </div>
      </div>
    </div>
  `;

  // Existing SOC functions should be called if available
  if (window.renderPresence) window.renderPresence();
  if (window.renderSLA) window.renderSLA();
}
