export function showToast(msg) {
  const el = document.createElement("div");
  el.className = "toast";
  el.innerText = msg;

  document.body.appendChild(el);

  setTimeout(() => el.remove(), 3000);
}

export function showLoading(el) {
  el.innerHTML = "<p>Analyzing activity...</p>";
}

export function highlight(el) {
  if (!el) return;
  el.classList.add("highlight");

  setTimeout(() => {
    el.classList.remove("highlight");
  }, 1500);
}

export function clearView(el) {
  if (el) el.innerHTML = "";
}

export function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function buildLocalAlertId(alert) {
  return alert.id || `${alert.sourceIp || "unknown"}-${alert.attackType || "alert"}-${alert.timestamp || Date.now()}`;
}
