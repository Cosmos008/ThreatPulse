export function buildAlertDetailMarkup(context) {
  const {
    alert,
    alertsForIp,
    attackTypesForIp,
    escalationBadge,
    highestSeverityLabel,
    coordinatedSequenceMarkup,
    previousTimelineMarkup,
    relatedAlertsMarkup,
    summaryBadgesMarkup,
    detailGridMarkup,
    indicatorsMarkup,
    analystMarkup,
    explanationMarkup,
    riskEvolutionMarkup,
    mitreMarkup,
    enrichmentMarkup,
    entityContextMarkup,
    iocMarkup,
    pivotMarkup,
    sourceIp,
    rawJson,
  } = context;

  return `
    <div class="detail-summary">
      <div class="detail-title-row">
        <strong>${alert.attackType}</strong>
        <div class="correlation-badges">${summaryBadgesMarkup}</div>
      </div>
      <div class="detail-grid">${detailGridMarkup}</div>
      ${indicatorsMarkup}
      ${analystMarkup}
      ${explanationMarkup}
      ${riskEvolutionMarkup}
      ${mitreMarkup}
    </div>
    ${enrichmentMarkup || ""}
    ${iocMarkup || ""}
    ${pivotMarkup || ""}
    <details class="detail-section detail-collapsible">
      <summary class="detail-collapse-summary">
        <strong>Entity Context</strong>
        ${escalationBadge}
      </summary>
      ${entityContextMarkup || ""}
    </details>
    ${coordinatedSequenceMarkup}
    <details class="detail-section detail-collapsible">
      <summary class="detail-collapse-summary">
        <strong>Previous activity timeline</strong>
        <span class="panel-note">${sourceIp}</span>
      </summary>
      ${previousTimelineMarkup}
    </details>
    <div class="detail-section">
      <strong>Related alerts</strong>
      ${relatedAlertsMarkup}
    </div>
    <details class="detail-section detail-collapsible">
      <summary class="detail-collapse-summary">
        <strong>Full event JSON</strong>
        <span class="panel-note">Collapsed by default</span>
      </summary>
      <pre class="detail-json">${rawJson}</pre>
    </details>
  `;
}
