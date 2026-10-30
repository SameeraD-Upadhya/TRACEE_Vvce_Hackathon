(function exposeReconstructionPresentation(root) {
  "use strict";

  function pageTotal(payload, collectionName) {
    const rows = Array.isArray(payload?.[collectionName]) ? payload[collectionName] : [];
    const total = payload?.pagination?.[collectionName]?.total;
    return Number.isInteger(total) && total >= 0 ? total : rows.length;
  }

  function hypothesisPresentation(hypothesis, evidenceId) {
    const interpretation = typeof hypothesis?.interpretation === "string"
      ? hypothesis.interpretation
      : "Unavailable";
    const supportingIds = Array.isArray(hypothesis?.supporting_observation_ids)
      ? hypothesis.supporting_observation_ids
      : null;
    const sourceEvidenceId = typeof evidenceId === "string" && evidenceId.length > 0
      ? evidenceId
      : null;
    const interpretationExplanation = interpretation === "corroborated"
      ? "The backend uses CORROBORATED when the configured rule's matching support checks pass without contradictions, input blockers, or unresolved conditions. This reconstruction uses observations from one evidence record; independent corroboration has not been established."
      : "Independent corroboration is not assessed by this single-evidence reconstruction workflow.";

    return {
      interpretation,
      supportingObservationCount: supportingIds === null ? null : supportingIds.length,
      distinctEvidenceRecordCount: sourceEvidenceId === null ? null : 1,
      evidenceId: sourceEvidenceId,
      independentCorroboration: "not_established",
      interpretationExplanation,
      causalityOrIncidentConclusion: "Not established; this is a rule-generated candidate hypothesis",
    };
  }

  const api = Object.freeze({ pageTotal, hypothesisPresentation });
  root.TraceeReconstructionPresentation = api;
  if (typeof module === "object" && module.exports) module.exports = api;
})(globalThis);
