import { state } from "./state.js";

const ASSIGNABLE_USERS_STORAGE_KEY = "cybermap.assignableUsers";

function normalizeAssignableUsers(values) {
  return [...new Set(
    (Array.isArray(values) ? values : [])
      .map(entry => typeof entry === "string" ? entry : entry?.username)
      .map(value => String(value || "").trim())
      .filter(Boolean)
  )];
}

function loadStoredAssignableUsers() {
  try {
    return normalizeAssignableUsers(JSON.parse(localStorage.getItem(ASSIGNABLE_USERS_STORAGE_KEY) || "[]"));
  } catch {
    localStorage.removeItem(ASSIGNABLE_USERS_STORAGE_KEY);
    return [];
  }
}

function persistAssignableUsers(values) {
  const normalized = normalizeAssignableUsers(values);
  if (normalized.length) {
    localStorage.setItem(ASSIGNABLE_USERS_STORAGE_KEY, JSON.stringify(normalized));
  } else {
    localStorage.removeItem(ASSIGNABLE_USERS_STORAGE_KEY);
  }
  return normalized;
}

function normalizeSessionUser(user) {
  if (!user || typeof user !== "object") {
    return user;
  }
  const assignableUsers = persistAssignableUsers(
    Array.isArray(user.assignableUsers)
      ? user.assignableUsers
      : (Array.isArray(user.assignable_users) ? user.assignable_users : loadStoredAssignableUsers())
  );
  return {
    ...user,
    assignableUsers,
  };
}

export function loginSuccess(user, apiKey) {
  const normalizedUser = normalizeSessionUser(user);
  state.user = normalizedUser;
  state.apiKey = apiKey;
  state.mode = "live";

  localStorage.setItem("session", JSON.stringify({
    user: normalizedUser,
    apiKey
  }));
}

export function loadSession() {
  let session = null;
  try {
    session = JSON.parse(localStorage.getItem("session"));
  } catch {
    localStorage.removeItem("session");
  }

  if (session) {
    state.user = normalizeSessionUser(session.user);
    state.apiKey = session.apiKey;
    state.mode = "live";
    return true;
  }
  return false;
}

export function logout() {
  state.user = null;
  state.apiKey = null;
  state.mode = "demo";
  localStorage.removeItem("session");
}
