import { state } from "./state.js";
import { highlightNewAlert } from "../main.js"; // This might need to be adjusted

export function createWebSocket(url, onMessage) {
  const ws = new WebSocket(url);

  ws.onopen = () => {
    console.log("Connected to SIEM live stream");
    if (window.showToast) window.showToast("Connected to live SOC stream");
  };

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    onMessage(data);
  };

  ws.onclose = () => {
    console.log("SIEM stream disconnected");
    if (window.showToast) window.showToast("Disconnected from live SOC stream");
    
    // Auto-reconnect
    setTimeout(() => createWebSocket(url, onMessage), 5000);
  };

  ws.onerror = (err) => {
    console.error("SIEM stream error", err);
  };

  return ws;
}
