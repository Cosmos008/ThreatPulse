const ALERT_LIFECYCLE_LABELS = {
  new: "New",
  in_case: "In Case",
  closed: "Closed",
  false_positive: "False Positive"
};

const ALERT_DISPOSITION_LABELS = {
  new: "New",
  acknowledged: "Acknowledged",
  suppressed: "Suppressed",
  reopened: "Reopened"
};

export function normalizeAlertLifecycle(alert = {}) {
  const explicitLifecycle = String(
    alert.lifecycle
    || alert.alertLifecycle
    || alert.alert_lifecycle
    || ""
  ).trim().toLowerCase();
  if (ALERT_LIFECYCLE_LABELS[explicitLifecycle]) {
    return explicitLifecycle;
  }

  const normalizedStatus = String(alert.status || "").trim().toLowerCase();
  if (alert.falsePositive || alert.false_positive || normalizedStatus === "false_positive") {
    return "false_positive";
  }
  if (alert.case_id || alert.caseId || alert.hasCase || normalizedStatus === "in_case" || normalizedStatus === "escalated" || normalizedStatus === "converted_to_case" || normalizedStatus === "processed") {
    return "in_case";
  }
  if (normalizedStatus === "closed") {
    return "closed";
  }
  return "new";
}

export function getAlertLifecycleLabel(lifecycle) {
  const normalized = normalizeAlertLifecycle({ lifecycle });
  return ALERT_LIFECYCLE_LABELS[normalized] || normalized;
}

export function normalizeAlertDisposition(alert = {}) {
  const explicitDisposition = String(
    alert.disposition
    || alert.alertDisposition
    || alert.alert_disposition
    || alert.details?.disposition
    || ""
  ).trim().toLowerCase();
  const mapping = {
    ack: "acknowledged",
    acknowledge: "acknowledged",
    acknowledged: "acknowledged",
    suppress: "suppressed",
    suppressed: "suppressed",
    reopen: "reopened",
    reopened: "reopened",
    new: "new"
  };
  const normalized = mapping[explicitDisposition] || explicitDisposition || "new";
  return ALERT_DISPOSITION_LABELS[normalized] ? normalized : "new";
}

export function getAlertDispositionLabel(disposition) {
  const normalized = normalizeAlertDisposition({ disposition });
  return ALERT_DISPOSITION_LABELS[normalized] || normalized;
}

export function canTransitionAlertDisposition(currentDisposition, nextDisposition) {
  const current = normalizeAlertDisposition({ disposition: currentDisposition });
  const next = normalizeAlertDisposition({ disposition: nextDisposition });
  const allowedTransitions = {
    new: new Set(["acknowledged", "suppressed"]),
    acknowledged: new Set(["suppressed"]),
    suppressed: new Set(["reopened"]),
    reopened: new Set(["acknowledged", "suppressed"])
  };
  if (current === next) {
    return true;
  }
  return allowedTransitions[current]?.has(next) || false;
}

export function isAlertEligibleForTriage(alert = {}) {
  const lifecycle = normalizeAlertLifecycle(alert);
  const disposition = normalizeAlertDisposition(alert);
  return lifecycle === "new" && disposition !== "suppressed";
}

export function applyAlertLifecycle(alert = {}, lifecycle, extra = {}) {
  const normalized = normalizeAlertLifecycle({ lifecycle });
  const nextStatus = normalized === "new" ? "new" : normalized;
  return {
    ...alert,
    ...extra,
    lifecycle: normalized,
    alertLifecycle: normalized,
    alert_lifecycle: normalized,
    status: nextStatus,
    false_positive: normalized === "false_positive" ? true : Boolean(extra.false_positive ?? alert.false_positive),
    falsePositive: normalized === "false_positive" ? true : Boolean(extra.falsePositive ?? alert.falsePositive)
  };
}

export function applyAlertDisposition(alert = {}, disposition, extra = {}) {
  const currentDisposition = normalizeAlertDisposition(alert);
  const normalizedDisposition = normalizeAlertDisposition({ disposition });
  if (!canTransitionAlertDisposition(currentDisposition, normalizedDisposition)) {
    throw new Error(`Invalid disposition transition: ${currentDisposition} -> ${normalizedDisposition}`);
  }
  const updatedAt = extra.updated_at ?? extra.updatedAt ?? Date.now();
  return {
    ...alert,
    ...extra,
    disposition: normalizedDisposition,
    alertDisposition: normalizedDisposition,
    alert_disposition: normalizedDisposition,
    updated_at: updatedAt,
    updatedAt
  };
}
