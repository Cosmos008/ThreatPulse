import { fetchStreamToken, normalizeAlertEvent } from "./snapshotClient.js";

function normalizeBaseUrl(value) {
  return String(value || "").replace(/\/+$/, "");
}

function getWebSocketUrl(apiBaseUrl) {
  const url = new URL(normalizeBaseUrl(apiBaseUrl));
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = "/ws";
  url.search = "";
  url.hash = "";
  return url.toString();
}

export function createLiveStream({ apiBaseUrl, apiKey, username, onEvent, onStatus, onError }) {
  let socket = null;
  let closedManually = false;
  let reconnectTimer = null;
  let hasConnected = false;

  function clearReconnectTimer() {
    if (reconnectTimer) {
      window.clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  }

  function close() {
    closedManually = true;
    clearReconnectTimer();
    if (socket) {
      socket.close();
      socket = null;
    }
  }

  async function connect() {
    close();
    closedManually = false;
    hasConnected = false;
    onStatus?.({ label: "CONNECTING LIVE", tone: "live" });

    const token = await fetchStreamToken(apiBaseUrl, apiKey, username);

    await new Promise((resolve, reject) => {
      let settled = false;

      function finish(handler, value) {
        if (settled) {
          return;
        }
        settled = true;
        handler(value);
      }

      try {
        socket = new WebSocket(getWebSocketUrl(apiBaseUrl));
      } catch (error) {
        onStatus?.({ label: "LIVE ERROR", tone: "error" });
        onError?.(error);
        reject(error);
        return;
      }

      socket.addEventListener("open", () => {
        hasConnected = true;
        socket.send(token);
        onStatus?.({ label: "LIVE", tone: "live" });
        finish(resolve);
      });

      socket.addEventListener("message", event => {
        try {
          const payload = JSON.parse(event.data);
          if (payload?.type) {
            onEvent?.(payload);
            return;
          }
          onEvent?.(normalizeAlertEvent(payload));
        } catch (error) {
          onError?.(new Error("Received malformed live alert payload."));
          console.error(error);
        }
      });

      socket.addEventListener("error", () => {
        const error = new Error("Live stream connection failed.");
        onError?.(error);
        if (!hasConnected) {
          onStatus?.({ label: "LIVE ERROR", tone: "error" });
          finish(reject, error);
        }
      });

      socket.addEventListener("close", () => {
        socket = null;
        if (closedManually) {
          finish(resolve);
          return;
        }

        if (!hasConnected) {
          const error = new Error("Live stream closed before authentication completed.");
          onStatus?.({ label: "LIVE ERROR", tone: "error" });
          finish(reject, error);
          return;
        }

        onStatus?.({ label: "LIVE RETRY", tone: "error" });
        clearReconnectTimer();
        reconnectTimer = window.setTimeout(() => {
          connect().catch(error => {
            onError?.(error);
          });
        }, 5000);
      });
    });
  }

  return {
    connect,
    close
  };
}
