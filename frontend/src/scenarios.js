export const scenarios = {
  credential_stuffing: (ip) => {
    return Array.from({ length: 20 }, (_, i) => ({
      id: "sim-cs-" + Date.now() + "-" + i,
      sourceIp: ip,
      attackType: "credential_stuffing",
      timestamp: Date.now() - i * 2000,
      severity: "high",
      status: "open",
      country: "US"
    }));
  },

  ddos_spike: (ip) => {
    return Array.from({ length: 50 }, (_, i) => ({
      id: "sim-ddos-" + Date.now() + "-" + i,
      sourceIp: ip,
      attackType: "rate_limit_abuse",
      timestamp: Date.now() - i * 500,
      severity: "critical",
      status: "open",
      country: "RU"
    }));
  },

  insider_threat: () => [
    {
      id: "sim-insider-" + Date.now(),
      sourceIp: "10.0.0.5",
      attackType: "anomaly_spike",
      severity: "medium",
      timestamp: Date.now(),
      status: "open",
      country: "LOCAL"
    }
  ]
};
