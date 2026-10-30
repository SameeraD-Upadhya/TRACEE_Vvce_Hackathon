"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const presentation = require("../ui/reconstruction-presentation.js");

test("dashboard labels local operation without claiming the API is read-only or connected", () => {
  const html = fs.readFileSync(path.join(__dirname, "../ui/index.html"), "utf8");
  assert.match(html, />LOCAL WORKSPACE</);
  assert.match(html, />API status is shown above</);
  assert.doesNotMatch(html, /LOCAL\s*\/\s*READ ONLY/i);
  assert.doesNotMatch(html, /Read-only API connection/i);
});

test("verification wording distinguishes unchanged evidence from its activity record", () => {
  const html = fs.readFileSync(path.join(__dirname, "../ui/index.html"), "utf8");
  assert.match(html, /Integrity verification does not modify the evidence payload; the verification result is recorded in activity history\./);
  assert.doesNotMatch(html, /The check is read-only/i);
});

test("uses API pagination totals rather than current page length", () => {
  const detail = {
    hypotheses: [{ hypothesis_id: "h-1" }],
    pagination: { hypotheses: { offset: 25, limit: 25, total: 26 } },
  };
  assert.equal(presentation.pageTotal(detail, "hypotheses"), 26);
});

test("uses zero total for an empty result and a validated row count when pagination is absent", () => {
  assert.equal(presentation.pageTotal({ hypotheses: [], pagination: { hypotheses: { total: 0 } } }, "hypotheses"), 0);
  assert.equal(presentation.pageTotal({ hypotheses: [{}, {}] }, "hypotheses"), 2);
  assert.equal(presentation.pageTotal({}, "hypotheses"), 0);
});

test("preserves backend corroborated value while explaining its limited scope", () => {
  const result = presentation.hypothesisPresentation({
    interpretation: "corroborated",
    supporting_observation_ids: ["obs-1", "obs-2"],
  }, "TRACE-EV-000001");

  assert.equal(result.interpretation, "corroborated");
  assert.equal(result.supportingObservationCount, 2);
  assert.equal(result.distinctEvidenceRecordCount, 1);
  assert.equal(result.evidenceId, "TRACE-EV-000001");
  assert.equal(result.independentCorroboration, "not_established");
  assert.match(result.interpretationExplanation, /independent corroboration has not been established/i);
  assert.match(result.causalityOrIncidentConclusion, /Not established/);
});

test("reports source and support counts as unavailable when the response lacks those fields", () => {
  const result = presentation.hypothesisPresentation({ interpretation: "underdetermined" }, null);
  assert.equal(result.interpretation, "underdetermined");
  assert.equal(result.supportingObservationCount, null);
  assert.equal(result.distinctEvidenceRecordCount, null);
  assert.match(result.interpretationExplanation, /not assessed/i);
});
