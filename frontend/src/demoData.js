const now = Date.now();


export const demoAlerts = [
  {
    sourceIp: "172.16.10.25",
    country: "US",
    userId: "svc-backup",
    deviceId: "srv-prod-fin-01",
    hostname: "srv-prod-fin-01",
    attackType: "honeypot_access",
    severity: "critical",
    timestamp: now - 2_000,
    riskScore: 165,
    details: { asset_criticality: "high", asn: "AS7018", city: "Ashburn", region: "Virginia" },
    indicators: ["Honeypot", "High confidence threat"],
    isHoneypot: true,
    raw: {
      rule: "honeypot_access",
      severity: "critical",
      risk_score: 165,
      confidence_label: "High confidence threat",
      details: { asset_criticality: "high", asn: "AS7018", city: "Ashburn", region: "Virginia" }
    }
  },
  { sourceIp: "8.8.8.8", country: "US", userId: "j.doe", deviceId: "wkst-4471", hostname: "wkst-4471", attackType: "credential_stuffing", severity: "high", riskScore: 88, details: { asset_criticality: "medium", city: "Chicago", region: "Illinois" }, timestamp: now - 5_000 },
  { sourceIp: "8.8.8.8", country: "US", userId: "j.doe", deviceId: "wkst-4471", hostname: "wkst-4471", attackType: "high_risk_actor", severity: "high", riskScore: 93, details: { asset_criticality: "medium", city: "Chicago", region: "Illinois" }, timestamp: now - 11_000 },
  { sourceIp: "203.0.113.10", country: "JP", userId: "svc-vpn", deviceId: "vpn-gateway-02", hostname: "vpn-gateway-02", attackType: "anomaly_spike", severity: "medium", riskScore: 61, details: { asset_criticality: "high", city: "Tokyo", region: "Tokyo" }, timestamp: now - 17_000 },
  { sourceIp: "198.51.100.24", country: "DE", userId: "m.klein", deviceId: "lap-2210", hostname: "lap-2210", attackType: "rate_limit_abuse", severity: "medium", riskScore: 59, details: { asset_criticality: "medium", city: "Berlin", region: "Berlin" }, timestamp: now - 23_000 },
  { sourceIp: "45.89.67.12", country: "BR", userId: "a.ortiz", deviceId: "edr-host-99", hostname: "edr-host-99", attackType: "device_abuse", severity: "high", riskScore: 84, details: { asset_criticality: "high", city: "Sao Paulo", region: "Sao Paulo" }, timestamp: now - 29_000 },
  { sourceIp: "198.51.100.24", country: "DE", userId: "m.klein", deviceId: "lap-2210", hostname: "lap-2210", attackType: "credential_stuffing", severity: "high", riskScore: 77, details: { asset_criticality: "medium", city: "Berlin", region: "Berlin" }, timestamp: now - 8 * 60 * 1000 },
  { sourceIp: "45.89.67.12", country: "BR", userId: "a.ortiz", deviceId: "edr-host-99", hostname: "edr-host-99", attackType: "device_abuse", severity: "high", riskScore: 86, details: { asset_criticality: "high", city: "Sao Paulo", region: "Sao Paulo" }, timestamp: now - 22 * 60 * 1000 },
  { sourceIp: "91.198.174.192", country: "NL", userId: "r.evans", deviceId: "wkst-9912", hostname: "wkst-9912", attackType: "credential_stuffing", severity: "high", riskScore: 82, details: { asset_criticality: "low", city: "Amsterdam", region: "North Holland" }, timestamp: now - 48 * 60 * 1000 },
  { sourceIp: "13.107.246.45", country: "IE", userId: "r.evans", deviceId: "wkst-9912", hostname: "wkst-9912", attackType: "high_risk_actor", severity: "high", riskScore: 90, details: { asset_criticality: "low", city: "Dublin", region: "Leinster" }, timestamp: now - 90 * 60 * 1000 },
  { sourceIp: "142.250.72.206", country: "US", userId: "payroll-admin", deviceId: "srv-hr-02", hostname: "srv-hr-02", attackType: "anomaly_spike", severity: "medium", riskScore: 72, details: { asset_criticality: "high", city: "New York", region: "New York" }, timestamp: now - 3 * 60 * 60 * 1000 },
  { sourceIp: "52.95.110.1", country: "SG", userId: "svc-data-sync", deviceId: "etl-node-7", hostname: "etl-node-7", attackType: "rate_limit_abuse", severity: "medium", riskScore: 68, details: { asset_criticality: "medium", city: "Singapore", region: "Singapore" }, timestamp: now - 7 * 60 * 60 * 1000 },
  { sourceIp: "20.27.177.113", country: "GB", userId: "a.ortiz", deviceId: "edr-host-99", hostname: "edr-host-99", attackType: "streaming_fraud", severity: "low", riskScore: 43, details: { asset_criticality: "high", city: "London", region: "England" }, timestamp: now - 18 * 60 * 60 * 1000 }
];
