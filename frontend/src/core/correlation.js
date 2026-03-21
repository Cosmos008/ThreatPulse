import { normalizeAlertEnrichment } from "./alertEnrichment.js";

function buildEmailDomain(email) {
  const normalized = String(email || "").trim().toLowerCase();
  const parts = normalized.split("@");
  return parts.length === 2 ? parts[1] : "";
}

export function buildCorrelationKeys(alert = {}) {
  const enrichment = normalizeAlertEnrichment(alert);
  const keys = [
    enrichment.ip && `ip:${String(enrichment.ip).toLowerCase()}`,
    enrichment.username && `user:${String(enrichment.username).toLowerCase()}`,
    enrichment.email && `email:${String(enrichment.email).toLowerCase()}`,
    enrichment.userEmail && `email:${String(enrichment.userEmail).toLowerCase()}`,
    enrichment.senderEmail && `email:${String(enrichment.senderEmail).toLowerCase()}`,
    enrichment.recipientEmail && `email:${String(enrichment.recipientEmail).toLowerCase()}`,
    enrichment.hostname && `host:${String(enrichment.hostname).toLowerCase()}`,
    enrichment.device && `device:${String(enrichment.device).toLowerCase()}`,
    buildEmailDomain(enrichment.email) && `domain:${buildEmailDomain(enrichment.email)}`,
    buildEmailDomain(enrichment.userEmail) && `domain:${buildEmailDomain(enrichment.userEmail)}`,
    buildEmailDomain(enrichment.senderEmail) && `domain:${buildEmailDomain(enrichment.senderEmail)}`,
    buildEmailDomain(enrichment.recipientEmail) && `domain:${buildEmailDomain(enrichment.recipientEmail)}`
  ].filter(Boolean);
  return [...new Set(keys)];
}

function unique(values = []) {
  return [...new Set(values.filter(Boolean))];
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function scoreCorrelationMatch(matchedFields = []) {
  const weights = {
    ip: 0.34,
    email: 0.3,
    domain: 0.18,
    user: 0.22,
    device: 0.18,
    host: 0.16
  };
  const score = matchedFields.reduce((total, field) => total + (weights[field] || 0.08), 0);
  return clamp(Number(score.toFixed(2)), 0.08, 0.99);
}

function getRuleSource(matchedFields = []) {
  if (matchedFields.includes("ip") && matchedFields.includes("user")) {
    return "multi_signal_ip_user";
  }
  if (matchedFields.includes("email") && matchedFields.includes("domain")) {
    return "email_domain_correlation";
  }
  if (matchedFields.includes("device") || matchedFields.includes("host")) {
    return "endpoint_identity_correlation";
  }
  if (matchedFields.includes("ip")) {
    return "shared_source_ip";
  }
  return "shared_entity_context";
}

function buildCorrelationReason(enrichment, candidateEnrichment, matchedFields = []) {
  const fragments = [];
  if (matchedFields.includes("ip")) {
    fragments.push(`same source IP (${enrichment.ip})`);
  }
  if (matchedFields.includes("user")) {
    fragments.push(`same user (${enrichment.username})`);
  }
  if (matchedFields.includes("email")) {
    const email = enrichment.email || enrichment.userEmail || enrichment.senderEmail || enrichment.recipientEmail;
    fragments.push(`same email (${email})`);
  }
  if (matchedFields.includes("domain")) {
    fragments.push(`same email/domain (${enrichment.domain})`);
  }
  if (matchedFields.includes("device")) {
    fragments.push(`same device (${enrichment.device})`);
  }
  if (matchedFields.includes("host")) {
    fragments.push(`same hostname (${enrichment.hostname || candidateEnrichment.hostname})`);
  }
  if (!fragments.length) {
    return "Related by shared entity context.";
  }
  return `Related because both alerts share ${fragments.join(", ")}.`;
}

export function explainAlertCorrelation(alert = {}, candidate = {}) {
  if (!candidate || String(candidate.id || "") === String(alert.id || "")) {
    return null;
  }
  const enrichment = normalizeAlertEnrichment(alert);
  const candidateEnrichment = normalizeAlertEnrichment(candidate);
  const matchedFields = unique([
    enrichment.ip && candidateEnrichment.ip && String(enrichment.ip).toLowerCase() === String(candidateEnrichment.ip).toLowerCase() ? "ip" : "",
    enrichment.username && candidateEnrichment.username && String(enrichment.username).toLowerCase() === String(candidateEnrichment.username).toLowerCase() ? "user" : "",
    enrichment.device && candidateEnrichment.device && String(enrichment.device).toLowerCase() === String(candidateEnrichment.device).toLowerCase() ? "device" : "",
    enrichment.hostname && candidateEnrichment.hostname && String(enrichment.hostname).toLowerCase() === String(candidateEnrichment.hostname).toLowerCase() ? "host" : "",
    buildEmailDomain(enrichment.email || enrichment.userEmail || enrichment.senderEmail || enrichment.recipientEmail)
      && buildEmailDomain(enrichment.email || enrichment.userEmail || enrichment.senderEmail || enrichment.recipientEmail)
        === buildEmailDomain(candidateEnrichment.email || candidateEnrichment.userEmail || candidateEnrichment.senderEmail || candidateEnrichment.recipientEmail)
      ? "domain" : "",
    [
      enrichment.email,
      enrichment.userEmail,
      enrichment.senderEmail,
      enrichment.recipientEmail
    ].filter(Boolean).some(value =>
      [
        candidateEnrichment.email,
        candidateEnrichment.userEmail,
        candidateEnrichment.senderEmail,
        candidateEnrichment.recipientEmail
      ].filter(Boolean).some(candidateValue => String(value).toLowerCase() === String(candidateValue).toLowerCase())
    ) ? "email" : ""
  ]);

  if (!matchedFields.length) {
    return null;
  }

  return {
    matchedFields,
    correlationReason: buildCorrelationReason(enrichment, candidateEnrichment, matchedFields),
    confidenceScore: scoreCorrelationMatch(matchedFields),
    ruleSource: getRuleSource(matchedFields)
  };
}

export function correlateRelatedAlerts(alert = {}, alerts = []) {
  return (Array.isArray(alerts) ? alerts : [])
    .map(candidate => {
      const explanation = explainAlertCorrelation(alert, candidate);
      return explanation ? { ...candidate, correlation: explanation } : null;
    })
    .filter(Boolean)
    .sort((left, right) =>
      (right.correlation?.confidenceScore || 0) - (left.correlation?.confidenceScore || 0)
    );
}
