function firstNonEmpty(...values) {
  for (const value of values) {
    if (value == null) {
      continue;
    }
    const text = String(value).trim();
    if (text) {
      return text;
    }
  }
  return "";
}

function collectCandidates(source, keys) {
  return keys.map(key => source?.[key]);
}

function pickField(alert, ...keyGroups) {
  const details = alert?.details || alert?.raw?.details || {};
  const raw = alert?.raw || {};
  for (const keys of keyGroups) {
    const value = firstNonEmpty(
      ...collectCandidates(alert || {}, keys),
      ...collectCandidates(details, keys),
      ...collectCandidates(raw, keys)
    );
    if (value) {
      return value;
    }
  }
  return "";
}

function joinLocation(...parts) {
  return parts.map(part => String(part || "").trim()).filter(Boolean).join(", ");
}

function uniqueStrings(values) {
  const seen = new Set();
  return values
    .map(value => String(value || "").trim())
    .filter(Boolean)
    .filter(value => {
      const marker = value.toLowerCase();
      if (seen.has(marker)) {
        return false;
      }
      seen.add(marker);
      return true;
    });
}

function flattenTextValues(value, bucket = [], limit = 200) {
  if (bucket.length >= limit || value == null) {
    return bucket;
  }
  if (Array.isArray(value)) {
    value.forEach(item => flattenTextValues(item, bucket, limit));
    return bucket;
  }
  if (typeof value === "object") {
    Object.values(value).forEach(item => flattenTextValues(item, bucket, limit));
    return bucket;
  }
  const text = String(value).trim();
  if (text) {
    bucket.push(text);
  }
  return bucket;
}

const IOC_PATTERNS = {
  ips: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  emails: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b/gi,
  domains: /\b(?=.{4,253}\b)(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}\b/gi,
  hashes: /\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b/gi
};

function extractPatternMatches(text, pattern) {
  return uniqueStrings(Array.from(String(text || "").matchAll(pattern), match => match[0]));
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function getAlertPrimaryIp(alert) {
  return pickField(
    alert,
    ["sourceIp", "source_ip", "src_ip", "ip", "source_address", "source", "client_ip"],
    ["destinationIp", "destination_ip", "dst_ip"]
  );
}

export function normalizeAlertEnrichment(alert) {
  const ip = getAlertPrimaryIp(alert);
  const destinationIp = pickField(alert, ["destinationIp", "destination_ip", "dst_ip", "dest_ip"]);
  const country = pickField(alert, ["country", "country_code", "countryCode"]);
  const region = pickField(alert, ["region", "region_name", "regionName", "state", "province"]);
  const city = pickField(alert, ["city", "city_name", "locality"]);
  const asn = pickField(alert, ["asn", "asn_org", "asnOrg"]);
  const isp = pickField(alert, ["isp", "provider", "asn_provider", "asnProvider"]);
  const username = pickField(alert, ["userId", "user_id", "username", "account", "account_name", "principal"]);
  const hostname = pickField(alert, ["hostname", "host", "host_name", "hostName", "endpoint", "endpoint_name"]);
  const device = pickField(alert, ["deviceId", "device_id", "device", "device_name", "deviceName"]);
  const deviceOs = pickField(alert, ["os", "device_os", "deviceOs", "platform"]);
  const browser = pickField(alert, ["browser", "user_agent", "userAgent", "ua"]);
  const email = pickField(alert, ["email", "user_email", "account_email", "mail"]);
  const senderEmail = pickField(alert, ["sender_email", "sender", "from", "from_email"]);
  const recipientEmail = pickField(alert, ["recipient_email", "recipient", "to", "to_email"]);
  const userEmail = pickField(alert, ["user_email", "account_email", "email"]);
  const account = pickField(alert, ["account", "account_name", "principal", "identity"]);
  const domain = firstNonEmpty(
    pickField(alert, ["domain", "sender_domain", "recipient_domain"]),
    String(email || userEmail || senderEmail || recipientEmail || "").split("@")[1]
  );
  const location = joinLocation(city, region, country);
  const emailLocalPart = firstNonEmpty(
    String(email || userEmail || senderEmail || recipientEmail || "").split("@")[0]
  );

  return {
    ip,
    destinationIp,
    country,
    region,
    city,
    location,
    asn,
    isp,
    username,
    account,
    hostname,
    device,
    deviceOs,
    browser,
    email,
    senderEmail,
    recipientEmail,
    userEmail,
    emailLocalPart,
    domain,
    threatLevel: firstNonEmpty(alert?.threatLevel, alert?.threat_level, alert?.details?.threat_level),
    riskScore: Number(alert?.riskScore ?? alert?.risk_score ?? alert?.details?.risk_score ?? 0) || 0,
    attackType: firstNonEmpty(alert?.attackType, alert?.attack_type, alert?.rule),
    severity: firstNonEmpty(alert?.severity),
    status: firstNonEmpty(alert?.status),
    relatedEntity: firstNonEmpty(
      pickField(alert, ["entity_key", "entityKey"]),
      pickField(alert, ["network_id", "networkId"]),
      pickField(alert, ["account_id", "accountId"])
    )
  };
}

export function normalizeAlertIocs(alert) {
  const provided = alert?.iocs || alert?.details?.iocs || alert?.raw?.iocs || {};
  const textCorpus = flattenTextValues(alert).join("\n");
  const enrichment = normalizeAlertEnrichment(alert);
  const emails = uniqueStrings([
    ...(provided.emails || []),
    ...extractPatternMatches(textCorpus, IOC_PATTERNS.emails),
    enrichment.email,
    enrichment.senderEmail,
    enrichment.recipientEmail,
    enrichment.userEmail
  ]);
  const domains = uniqueStrings([
    ...(provided.domains || []),
    ...extractPatternMatches(textCorpus, IOC_PATTERNS.domains),
    enrichment.domain,
    ...emails.map(email => email.includes("@") ? email.split("@")[1] : "")
  ]);
  const ips = uniqueStrings([
    ...(provided.ips || []),
    ...extractPatternMatches(textCorpus, IOC_PATTERNS.ips),
    enrichment.ip,
    enrichment.destinationIp
  ]);
  const hashes = uniqueStrings([
    ...(provided.hashes || []),
    ...extractPatternMatches(textCorpus, IOC_PATTERNS.hashes)
  ]);
  const usernames = uniqueStrings([
    ...(provided.usernames || []),
    enrichment.username,
    enrichment.account
  ]);
  const hostnames = uniqueStrings([
    ...(provided.hostnames || []),
    enrichment.hostname,
    enrichment.device
  ]);
  return {
    ips,
    domains,
    emails,
    hashes,
    usernames,
    hostnames
  };
}

export function buildIocChipGroups(alert) {
  const iocs = normalizeAlertIocs(alert);
  return [
    { key: "ips", label: "IPs", values: iocs.ips },
    { key: "domains", label: "Domains", values: iocs.domains },
    { key: "emails", label: "Emails", values: iocs.emails },
    { key: "hashes", label: "Hashes", values: iocs.hashes },
    { key: "usernames", label: "Usernames", values: iocs.usernames },
    { key: "hostnames", label: "Hostnames", values: iocs.hostnames }
  ].filter(group => group.values.length);
}

export function highlightIocsInText(text, alert) {
  const chipGroups = buildIocChipGroups(alert);
  if (!text) {
    return "";
  }
  const tokens = uniqueStrings(chipGroups.flatMap(group => group.values)).sort((left, right) => right.length - left.length);
  if (!tokens.length) {
    return escapeHtml(text);
  }
  const pattern = new RegExp(`(${tokens.map(token => token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})`, "gi");
  return escapeHtml(text).replace(pattern, '<mark class="ioc-highlight">$1</mark>');
}
