import { state } from "./state.js";

export function getHeaders() {
  if (state.mode === "demo") {
    throw new Error("API disabled in demo");
  }

  if (!state.apiKey) {
    throw new Error("API key missing");
  }

  const headers = {
    "Content-Type": "application/json",
    "X-API-Key": state.apiKey
  };
  if (state.user?.username) {
    headers["X-User"] = state.user.username;
  }
  return headers;
}

export function apiFetch(url, options = {}) {
  const headers = getHeaders();
  return fetch(url, {
    ...options,
    headers: {
      ...headers,
      ...options.headers
    }
  });
}
