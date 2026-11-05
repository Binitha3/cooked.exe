(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const elements = {
    caseSelect: $("#case-select"),
    title: $("#case-title"),
    requestText: $("#request-text"),
    requestedAt: $("#requested-at"),
    auditAt: $("#audit-at"),
    reportedStatus: $("#reported-status"),
    verdict: $("#verdict"),
    verdictMessage: $("#verdict-message"),
    verdictPanel: $(".verdict-panel"),
    verdictSpark: $("#verdict-spark"),
    counter: $("#residual-counter"),
    observationCount: $("#observation-count"),
    traceList: $("#trace-list"),
    filters: $("#filters"),
    verifyButton: $("#verify-button"),
    buttonLabel: $(".button-label"),
    stageCase: $("#stage-case"),
    stageStatus: $("#stage-status"),
    map: $("#ghost-map"),
    mapCaption: $("#map-caption"),
    mapProvenance: $("#map-provenance"),
    stepTotal: $("#step-total"),
    stepList: $("#step-list"),
    timelineTotal: $("#timeline-total"),
    timelineList: $("#timeline-list"),
    riskTotal: $("#risk-total"),
    riskList: $("#risk-list"),
    rebirthStatus: $("#rebirth-status"),
    rebirthList: $("#rebirth-list"),
    drawer: $("#evidence-drawer"),
    drawerTitle: $("#drawer-title"),
    drawerContent: $("#drawer-content"),
    closeDrawer: $("#close-drawer"),
    toast: $("#toast"),
  };

  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  let cases = [];
  let caseById = new Map();
  let currentResult = null;
  let currentFilter = "ALL";
  let focusedResource = null;
  let sweepStarted = 0;
  let sweepUntil = 0;
  let pointer = { x: -1000, y: -1000 };
  let particles = [];
  let toastTimer = 0;

  function text(node, value) {
    node.textContent = value == null ? "—" : String(value);
  }

  function showToast(message) {
    text(elements.toast, message);
    elements.toast.classList.add("is-visible");
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => elements.toast.classList.remove("is-visible"), 2600);
  }

  function formatTime(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium", timeStyle: "short", timeZone: "UTC",
    }).format(date) + " UTC";
  }

  function currentCase() {
    return caseById.get(elements.caseSelect.value) || null;
  }

  async function loadCases() {
    const response = await fetch("/api/cases", { cache: "no-store" });
    if (!response.ok) throw new Error(`Request catalog returned ${response.status}`);
    const payload = await response.json();
    cases = payload.cases || [];
    caseById = new Map(cases.map((item) => [item.case_id, item]));
    elements.caseSelect.replaceChildren();
    for (const item of cases) {
      const option = document.createElement("option");
      option.value = item.case_id;
      option.textContent = `${item.dataset_group} / ${item.case_id}  ·  ${item.audit_at.slice(0, 10)}  ·  ${item.email}`;
      elements.caseSelect.append(option);
    }
    const initial = caseById.has("case_16") ? "case_16" : cases[0]?.case_id;
    if (initial) {
      elements.caseSelect.value = initial;
      showCaseHeader(currentCase());
      await runVerification();
    }
  }

  function showCaseHeader(item) {
    if (!item) return;
    text(elements.title, item.case_id);
    text(elements.requestText, item.request_text);
    text(elements.requestedAt, formatTime(item.requested_at));
    text(elements.auditAt, formatTime(item.audit_at));
    text(elements.reportedStatus, `${item.reported_status} · CLAIM ONLY`);
    text(elements.stageCase, item.case_id);
    resetResult("NOT YET RUN", "Run verification to invoke the real audit pipeline.", null);
    renderObservationList([]);
    renderGraph(null, null, null);
    drawParticles([]);
  }

  function resetResult(label, message, status) {
    text(elements.verdict, label);
    text(elements.verdictMessage, message);
    elements.verdictPanel.dataset.status = status || "";
    elements.verdictSpark.style.background = statusColor(status);
    text(elements.counter, "—");
    text(elements.observationCount, "—");
    text(elements.stepTotal, "—");
    elements.stepList.replaceChildren(makeDimCopy("No policy decision yet."));
    text(elements.timelineTotal, "NOT RUN");
    elements.timelineList.replaceChildren(makeDimCopy("Run verification to view cutoff-valid evidence events."));
    text(elements.riskTotal, "NOT RUN");
    elements.riskList.replaceChildren(makeDimCopy("Run verification to build evidence-backed explanations."));
    text(elements.rebirthStatus, "NOT RUN");
    elements.rebirthList.replaceChildren(makeDimCopy("Reappearance analysis has not run."));
    elements.filters.replaceChildren();
    currentResult = null;
    currentFilter = "ALL";
  }

  async function runVerification() {
    const item = currentCase();
    if (!item || elements.verifyButton.disabled) return;
    elements.verifyButton.disabled = true;
    elements.verifyButton.classList.add("is-running");
    elements.buttonLabel.textContent = "Reviewing evidence…";
    elements.stageStatus.classList.add("is-active");
    elements.stageStatus.classList.remove("is-residual");
    elements.stageStatus.lastElementChild.textContent = "RUNNING THE AUDIT PIPELINE";
    resetResult("ANALYZING", "Identity, evidence, and policy checks are running. No records will be changed.", null);
    startSweep();

    let payload;
    try {
      const response = await fetch("/api/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ case_id: item.case_id }),
      });
      payload = await response.json();
      if (!response.ok) throw new Error(payload.error || `Verification returned ${response.status}`);
    } catch (error) {
      finishSweep();
      resetResult("PIPELINE UNAVAILABLE", error.message || "Could not reach the local audit service.", "UNRESOLVED");
      elements.stageStatus.classList.remove("is-active");
      elements.stageStatus.lastElementChild.textContent = "AUDIT SERVICE UNAVAILABLE";
      showToast("The pipeline call failed; no deletion was performed.");
      endButton();
      return;
    }

    const wait = reducedMotion.matches ? 0 : Math.max(0, sweepUntil - performance.now());
    window.setTimeout(() => {
      finishSweep();
      currentResult = payload;
      renderResult(payload);
      endButton();
    }, wait);
  }

  function endButton() {
    elements.verifyButton.disabled = false;
    elements.verifyButton.classList.remove("is-running");
    elements.buttonLabel.textContent = "Run verification";
  }

  function startSweep() {
    sweepStarted = performance.now();
    sweepUntil = sweepStarted + (reducedMotion.matches ? 0 : 1700);
  }

  function finishSweep() {
    sweepUntil = 0;
    sweepStarted = 0;
  }

  function renderResult(result) {
    const status = result.deletion_status;
    const intentAmbiguous = result.pipeline_state === "INTENT_AMBIGUOUS";
    const unresolved = !status && !intentAmbiguous;
    const heading = status || (intentAmbiguous ? "INTENT AMBIGUOUS" : "POLICY UNRESOLVED");
    const visualStatus = status || (intentAmbiguous ? "AMBIGUOUS" : "UNRESOLVED");
    text(elements.verdict, heading);
    text(elements.verdictMessage, result.message);
    elements.verdictPanel.dataset.status = visualStatus;
    elements.verdictSpark.style.background = statusColor(visualStatus);
    text(elements.counter, result.residual_count == null ? "—" : String(result.residual_count).padStart(2, "0"));
    text(elements.observationCount, result.observations?.length ?? 0);
    text(elements.stepTotal, status ? `${result.steps.length} STEPS` : "NO DECISION");
    elements.stepList.replaceChildren();
    if (result.steps?.length) {
      for (const step of result.steps) elements.stepList.append(makeStep(step));
    } else {
      elements.stepList.append(makeDimCopy(intentAmbiguous
        ? "Authorization is unclear. The pipeline did not search evidence or make a deletion decision."
        : unresolved ? result.message : "No policy steps were returned."));
    }
    renderFilters(result.observations || [], result.steps || []);
    renderObservationList(result.observations || [], result.steps || []);
    renderGraph(result.ghost_data_map_json, result.ghost_data_map_error, result);
    renderTimeline(result);
    renderExplainability(result.explainability, result.explainability_error, result);
    renderRebirth(result.rebirth);
    drawParticles(resourcePoints(result));
    if (intentAmbiguous) {
      elements.stageStatus.classList.remove("is-active", "is-residual");
      elements.stageStatus.lastElementChild.textContent = "NO EVIDENCE SEARCH · AUTHORIZATION UNRESOLVED";
    } else if (unresolved) {
      elements.stageStatus.classList.remove("is-active", "is-residual");
      elements.stageStatus.lastElementChild.textContent = "POLICY RESULT UNRESOLVED";
    } else {
      elements.stageStatus.classList.remove("is-active");
      elements.stageStatus.classList.toggle("is-residual", result.residual_count > 0);
      elements.stageStatus.lastElementChild.textContent = result.residual_count > 0
        ? `${result.residual_count} EVIDENCE-BACKED RESIDUAL RESOURCE${result.residual_count === 1 ? "" : "S"}`
        : "NO EVIDENCE-BACKED RESIDUAL RESOURCES FOUND";
    }
  }

  function renderTimeline(result) {
    elements.timelineList.replaceChildren();
    const cutoff = Date.parse(result.case?.audit_at || "");
    const events = Object.entries(result.evidence || {}).flatMap(([evidenceId, item]) => {
      const recordTime = item.record_timestamp || null;
      const capturedTime = item.captured_at || null;
      const timestamp = recordTime || capturedTime;
      const parsed = timestamp ? Date.parse(timestamp) : NaN;
      if (!Number.isFinite(parsed) || !Number.isFinite(cutoff) || parsed > cutoff) return [];
      let title;
      let description;
      if (item.source_type === "ACTIVITY_EVENT") {
        title = `${item.event_type} · ACTIVITY CLAIM`;
        description = [item.activity_id, item.source_system, item.target_system, item.resource_id, item.reported_result ? `reported ${item.reported_result}` : ""].filter(Boolean).join(" · ");
      } else if (item.source_type === "IDENTITY_AUDIT") {
        title = `IDENTITY AUDIT · ${item.field_name}`;
        description = `${item.audit_id} · identity history reference`;
      } else {
        title = `EVIDENCE FILE · ${item.format || "unknown format"}`;
        description = [item.file_id, item.relative_path, item.locator, recordTime ? `record ${formatTime(recordTime)}` : "record time unavailable", capturedTime ? `captured ${formatTime(capturedTime)}` : ""].filter(Boolean).join(" · ");
      }
      return [{ evidenceId, timestamp, parsed, title, description }];
    }).sort((left, right) => left.parsed - right.parsed || left.evidenceId.localeCompare(right.evidenceId));
    text(elements.timelineTotal, `${events.length} SOURCES`);
    if (!events.length) {
      elements.timelineList.append(makeDimCopy("No cutoff-valid timestamped evidence references are available for this investigation."));
      return;
    }
    for (const event of events) {
      const row = document.createElement("article");
      row.className = "timeline-event";
      const timestamp = document.createElement("time");
      timestamp.dateTime = event.timestamp;
      timestamp.textContent = formatTime(event.timestamp);
      const title = document.createElement("strong");
      title.textContent = event.title;
      const description = document.createElement("p");
      description.textContent = event.description;
      row.append(timestamp, title, description);
      elements.timelineList.append(row);
    }
  }

  function renderExplainability(payload, error, result) {
    const report = payload?.investigation;
    const cards = report?.risk_cards || [];
    text(elements.riskTotal, report ? `${cards.length} CARDS` : "UNAVAILABLE");
    elements.riskList.replaceChildren();
    if (!report) {
      elements.riskList.append(makeDimCopy(error || "Policy decision unavailable; no explainability report was produced."));
      return;
    }
    for (const card of cards) {
      const article = document.createElement("article");
      article.className = "risk-card";
      const heading = document.createElement("div");
      heading.className = "risk-card-heading";
      const title = document.createElement("strong");
      title.textContent = card.title;
      const severity = document.createElement("span");
      severity.className = `severity severity-${String(card.severity).toLowerCase()}`;
      severity.textContent = `${card.severity} · ${card.category}`;
      heading.append(title, severity);
      article.append(heading);
      article.append(detailCopy("DISCOVERED", card.what_was_discovered));
      article.append(detailCopy("WHY IT MATTERS", card.why_it_matters));
      article.append(detailCopy("POTENTIAL CONSEQUENCE", card.potential_consequence));
      const refs = document.createElement("div");
      refs.className = "risk-evidence";
      refs.append(detailCopy("EVIDENCE / PROVENANCE", ""));
      for (const item of card.evidence || []) {
        const line = document.createElement("p");
        line.textContent = [item.evidence_id, item.source_file, item.locator,
          item.record_timestamp ? `record ${formatTime(item.record_timestamp)}` : "record time unknown",
          item.captured_at ? `captured ${formatTime(item.captured_at)}` : "capture time unknown",
          item.supporting_observation?.activity_id ? `activity ${item.supporting_observation.activity_id}` : "",
          ...(item.uncertainty || []).map((value) => `uncertainty: ${value}`),
        ].filter(Boolean).join(" · ");
        refs.append(line);
      }
      article.append(refs);
      if (card.uncertainty?.length) article.append(detailCopy("UNCERTAINTY", card.uncertainty.join(" · ")));
      article.append(detailCopy("RECOMMENDED REMEDIATION", `${card.recommended_action}${card.is_policy_violation === false ? " · POLICY RETENTION" : " · PROPOSED ONLY"}`));
      for (const req of card.verification_requirements || []) {
        article.append(detailCopy("FOLLOW-UP VERIFICATION", `${req.system_id} / ${req.resource_id} · ${req.operation} → ${req.expected_state}${req.unresolved?.length ? ` · ${req.unresolved.join("; ")}` : ""}`));
      }
      const actions = new Set(["DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD", "DISABLE_DATA_FLOW", "BLOCK_RESTORE"]);
      if (actions.has(card.recommended_action) && result.case?.case_id) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "whatif-button";
        button.textContent = `Preview ${card.recommended_action.replaceAll("_", " ")} · WHAT-IF ONLY`;
        button.addEventListener("click", () => runWhatIf(result.case.case_id, card.risk_id, card.recommended_action, article));
        article.append(button);
      }
      elements.riskList.append(article);
    }
    if (!cards.length) elements.riskList.append(makeDimCopy("No explainable policy risk cards were returned for this decision."));
  }

  async function runWhatIf(caseId, riskId, action, container) {
    const prior = container.querySelector(".whatif-preview");
    if (prior) prior.remove();
    const button = container.querySelector(".whatif-button");
    if (button) button.disabled = true;
    try {
      const response = await fetch("/api/what-if", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ case_id: caseId, risk_id: riskId, proposed_action: action }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || `Preview returned ${response.status}`);
      const preview = document.createElement("div");
      preview.className = "whatif-preview";
      preview.append(detailCopy("SIMULATION ONLY · NO ACTION EXECUTED", `${payload.proposed_action} · original decision remains ${payload.decision_status_after_preview}`));
      preview.append(detailCopy("EXPECTED RISK REDUCTION", (payload.expected_risk_reduction || []).join(" · ") || "No reduction asserted"));
      preview.append(detailCopy("SCOPE", payload.risk_reduction_scope));
      preview.append(detailCopy("REMAINING DEPENDENCIES", JSON.stringify(payload.dependencies_remaining || [])));
      preview.append(detailCopy("REQUIRED VERIFICATION", (payload.verification_requirements || []).map((req) => `${req.system_id}/${req.resource_id}: ${req.operation} → ${req.expected_state}`).join(" · ") || "None listed"));
      if (payload.unresolved?.length) preview.append(detailCopy("UNRESOLVED", payload.unresolved.join(" · ")));
      container.append(preview);
    } catch (error) {
      const preview = document.createElement("div");
      preview.className = "whatif-preview";
      preview.append(makeDimCopy(`What-If preview unavailable: ${error.message}`));
      container.append(preview);
    } finally {
      if (button) button.disabled = false;
    }
  }

  function detailCopy(label, value) {
    const wrap = document.createElement("p");
    wrap.className = "risk-copy";
    const key = document.createElement("span");
    key.textContent = `${label} · `;
    const content = document.createElement("span");
    content.textContent = value == null || value === "" ? "Not supplied" : String(value);
    wrap.append(key, content);
    return wrap;
  }

  function renderRebirth(payload) {
    elements.rebirthList.replaceChildren();
    if (!payload) {
      text(elements.rebirthStatus, "NOT EVALUATED");
      elements.rebirthList.append(makeDimCopy("Rebirth detection was not evaluated because authorization or identity resolution did not complete."));
      return;
    }
    const findings = payload.findings || [];
    const statuses = [...new Set(findings.map((item) => item.status))];
    text(elements.rebirthStatus, statuses.join(" / ") || payload.analysis_status || "NO FINDING");
    if (!findings.length) {
      elements.rebirthList.append(makeDimCopy(payload.message || "No rebirth finding was returned."));
      return;
    }
    for (const finding of findings) {
      const article = document.createElement("article");
      article.className = `rebirth-card${finding.status === "CONFIRMED_REAPPEARANCE" ? " is-confirmed" : ""}`;
      const title = document.createElement("strong");
      title.textContent = finding.status.replaceAll("_", " ");
      article.append(title);
      article.append(detailCopy("ORIGINAL RECORD", [finding.original_system_id, finding.original_resource_id].filter(Boolean).join(" / ") || "Not established"));
      article.append(detailCopy("DELETION VERIFICATION", (finding.deletion_evidence_ids || []).join(", ") || "No evidence-backed deletion verification"));
      article.append(detailCopy("LATER OBSERVATION", [finding.reappeared_system_id, finding.reappeared_resource_id].filter(Boolean).join(" / ") || "Not established"));
      article.append(detailCopy("SUPPORTING EVIDENCE", [...(finding.baseline_evidence_ids || []), ...(finding.deletion_evidence_ids || []), ...(finding.later_evidence_ids || [])].join(", ") || "None"));
      article.append(detailCopy("EXPLANATION", finding.match_explanation));
      article.append(detailCopy("CAUSE", finding.cause ? `${finding.cause} · ${finding.cause_evidence_ids.join(", ")}` : "No cause established by evidence"));
      article.append(detailCopy("CORRECTIVE ACTION", `${finding.recommended_action} · recommended, not executed`));
      article.append(detailCopy("FOLLOW-UP", finding.follow_up_verification));
      if (finding.trail?.length) {
        const trail = document.createElement("ol");
        trail.className = "rebirth-trail";
        for (const event of finding.trail) {
          const item = document.createElement("li");
          item.textContent = `${formatTime(event.timestamp)} · ${event.kind.replaceAll("_", " ")} · ${event.system_id}/${event.resource_id} · ${event.description} · evidence ${(event.evidence_ids || []).join(", ")}`;
          trail.append(item);
        }
        article.append(trail);
      }
      elements.rebirthList.append(article);
    }
    if (payload.input_summary && payload.input_summary.scope_established !== true) {
      elements.rebirthList.append(detailCopy("COVERAGE LIMIT", payload.message || "Complete evidence-backed coverage is unavailable; absence cannot be concluded."));
    }
  }

  function makeStep(step) {
    const row = document.createElement("div");
    row.className = "step-item";
    const number = document.createElement("span");
    number.className = "step-no";
    number.textContent = String(step.step_no).padStart(2, "0");
    const resource = document.createElement("span");
    resource.className = "step-resource";
    resource.textContent = `${step.system_id} / ${step.resource_id} · ${step.state}`;
    const operation = document.createElement("span");
    operation.className = "step-op";
    operation.textContent = step.operation.replaceAll("_", " ");
    row.append(number, resource, operation);
    return row;
  }

  function makeDimCopy(value) {
    const node = document.createElement("p");
    node.className = "dim-copy";
    node.textContent = value;
    return node;
  }

  function residualKeys(steps) {
    const operations = new Set([
      "REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII",
      "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK",
    ]);
    return new Set((steps || [])
      .filter((step) => step.phase === "FINDING" && operations.has(step.operation))
      .map((step) => `${step.system_id}\u0000${step.resource_id}`));
  }

  function verifiedKeys(steps) {
    return new Set((steps || [])
      .filter((step) => step.phase === "VERIFICATION")
      .map((step) => `${step.system_id}\u0000${step.resource_id}`));
  }

  function observationClass(observation, result) {
    const key = `${observation.system_id}\u0000${observation.resource_id}`;
    if (residualKeys(result?.steps).has(key)) return "residual";
    if (verifiedKeys(result?.steps).has(key)) return "verified";
    return "unresolved";
  }

  function renderFilters(observations, steps) {
    const available = [
      { id: "ALL", label: "ALL" },
      { id: "residual", label: "RESIDUAL" },
      { id: "verified", label: "VERIFIED" },
      { id: "unresolved", label: "UNRESOLVED" },
    ];
    const categories = [...new Set(observations.map((item) => item.data_category).filter(Boolean))].sort();
    for (const category of categories) available.push({ id: `category:${category}`, label: category.replaceAll("_", " ") });
    elements.filters.replaceChildren();
    for (const filter of available) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "filter-chip";
      button.textContent = filter.label;
      button.dataset.filter = filter.id;
      button.setAttribute("aria-pressed", String(currentFilter === filter.id));
      button.addEventListener("click", () => {
        currentFilter = filter.id;
        renderFilters(observations, steps);
        renderObservationList(observations, steps);
      });
      elements.filters.append(button);
    }
  }

  function renderObservationList(observations, steps = currentResult?.steps || []) {
    elements.traceList.replaceChildren();
    const result = currentResult || { steps };
    const filtered = observations.filter((item) => {
      if (currentFilter === "ALL") return true;
      if (currentFilter.startsWith("category:")) return item.data_category === currentFilter.slice(9);
      return observationClass(item, result) === currentFilter;
    });
    if (!filtered.length) {
      elements.traceList.append(makeDimCopy(observations.length
        ? "No discovered resources match this filter."
        : "No evidence-backed observations are available for this request."));
      return;
    }
    for (const observation of filtered) {
      const verdict = observationClass(observation, result);
      const card = document.createElement("button");
      card.type = "button";
      card.className = "trace-card";
      card.setAttribute("role", "listitem");
      card.dataset.verdict = verdict;
      card.dataset.resourceId = observation.resource_id;
      card.dataset.systemId = observation.system_id;
      const topline = document.createElement("div");
      topline.className = "trace-topline";
      const titleBlock = document.createElement("div");
      const title = document.createElement("p");
      title.className = "trace-title";
      title.textContent = observation.resource_id;
      const system = document.createElement("p");
      system.className = "trace-system";
      system.textContent = `${observation.system_id} · ${observation.data_category}`;
      titleBlock.append(title, system);
      const state = document.createElement("span");
      state.className = `state-pill ${verdict}${observation.observed_state === "ACTIVE" ? " active" : ""}`;
      state.textContent = `${verdict.replaceAll("_", " ")} · ${observation.observed_state}`;
      topline.append(titleBlock, state);
      const visual = document.createElement("div");
      visual.className = "trace-visual";
      visual.setAttribute("aria-hidden", "true");
      for (let index = 0; index < 5; index++) {
        const dot = document.createElement("i");
        dot.className = "signal-dot";
        visual.append(dot);
      }
      const meta = document.createElement("div");
      meta.className = "trace-meta";
      const evidence = document.createElement("span");
      evidence.textContent = observation.evidence_references.join(" · ") || "NO EVIDENCE REFERENCE";
      const time = document.createElement("span");
      time.textContent = observation.observation_timestamp ? formatTime(observation.observation_timestamp) : "TIME UNKNOWN";
      meta.append(evidence, time);
      card.append(topline, visual, meta);
      card.addEventListener("mouseenter", () => focusResource(observation));
      card.addEventListener("focus", () => focusResource(observation));
      card.addEventListener("mouseleave", () => focusResource(null));
      card.addEventListener("blur", () => focusResource(null));
      card.addEventListener("click", () => openDrawer(observation, result));
      elements.traceList.append(card);
    }
  }

  function openDrawer(observation, result) {
    text(elements.drawerTitle, observation.resource_id);
    elements.drawerContent.replaceChildren();
    addDrawerSection("RESOURCE OBSERVATION", [
      ["SYSTEM", observation.system_id],
      ["CATEGORY", observation.data_category],
      ["OBSERVED STATE", observation.observed_state],
      ["RECORD TIME", observation.observation_timestamp ? formatTime(observation.observation_timestamp) : "UNKNOWN"],
      ["IDENTIFIERS", (observation.identifiers || []).map((item) => `${item.type}: ${item.value}`).join(" · ") || "NONE"],
    ]);

    const evidenceIds = observation.evidence_references || [];
    if (evidenceIds.length) {
      const evidenceSection = makeSection("EVIDENCE TRAIL");
      for (const evidenceId of evidenceIds) {
        const record = result.evidence?.[evidenceId];
        evidenceSection.append(detailRow("REFERENCE ID", evidenceId));
        if (!record) {
          evidenceSection.append(makeDimCopy("The source record for this reference is not present in the loaded evidence index."));
          continue;
        }
        if (record.source_type === "EVIDENCE_FILE") {
          evidenceSection.append(detailRow("FILE ID", record.file_id));
          evidenceSection.append(detailRow("FILE PATH", record.relative_path));
          evidenceSection.append(detailRow("ORIGIN", record.origin));
          evidenceSection.append(detailRow("CAPTURED AT", formatTime(record.captured_at)));
          evidenceSection.append(detailRow("RECORD TIME", formatTime(record.record_timestamp)));
          evidenceSection.append(detailRow("FORMAT / PARSER", `${record.format} / ${record.parser_status}`));
          evidenceSection.append(detailRow("FILE LOCATOR", record.locator));
        } else if (record.source_type === "ACTIVITY_EVENT") {
          evidenceSection.append(detailRow("SOURCE", "SYSTEM ACTIVITY EVENT"));
          evidenceSection.append(detailRow("EVENT TYPE", record.event_type));
          evidenceSection.append(detailRow("EVENT TIME", formatTime(record.record_timestamp)));
          evidenceSection.append(detailRow("SOURCE → TARGET", `${record.source_system} → ${record.target_system}`));
          evidenceSection.append(detailRow("RESOURCE", record.resource_id));
          evidenceSection.append(detailRow("REPORTED RESULT · CLAIM", record.reported_result));
          evidenceSection.append(detailRow("DETAILS", JSON.stringify(record.details || {})));
        } else if (record.source_type === "IDENTITY_AUDIT") {
          evidenceSection.append(detailRow("SOURCE", "IDENTITY AUDIT EVENT"));
          evidenceSection.append(detailRow("AUDIT TIME", formatTime(record.record_timestamp)));
          evidenceSection.append(detailRow("FIELD CHANGED", record.field_name));
          evidenceSection.append(detailRow("STABLE USER ID", record.user_id));
        }
      }
      elements.drawerContent.append(evidenceSection);
    } else {
      elements.drawerContent.append(makeDimCopy("No evidence references are attached to this observation."));
    }

    const links = (result.trace_links || []).filter((link) =>
      link.system_id === observation.system_id && link.resource_id === observation.resource_id);
    if (links.length) {
      const section = makeSection("SAME-FILE TRACE CORRELATION");
      for (const link of links) {
        const trace = document.createElement("div");
        trace.className = "trace-evidence";
        const heading = document.createElement("strong");
        heading.textContent = `${link.trace_id} · ${link.evidence_id}`;
        const details = document.createElement("p");
        details.textContent = `Subject match ${link.identifier_locator} at ${formatTime(link.identifier_record_timestamp)} → resource ${link.resource_locator} at ${formatTime(link.resource_record_timestamp)}. Supported state: ${link.supported_state}.`;
        trace.append(heading, details);
        section.append(trace);
        for (const [name, value] of Object.entries(link.supported_fields || {})) {
          section.append(detailRow(name.replaceAll("_", " "), value));
        }
      }
      elements.drawerContent.append(section);
    }

    const relationships = observation.relationships || [];
    const relationshipSection = makeSection("OBSERVED RELATIONSHIPS");
    if (relationships.length) {
      for (const relationship of relationships) {
        const details = typeof relationship.details === "string"
          ? relationship.details
          : JSON.stringify(relationship.details);
        relationshipSection.append(detailRow(relationship.relationship, `${relationship.system_id} / ${relationship.resource_id}${details ? ` · ${details}` : ""}`));
      }
    } else {
      relationshipSection.append(makeDimCopy("No relationship was established for this resource."));
    }
    elements.drawerContent.append(relationshipSection);

    const resourceSteps = (result.steps || []).filter((step) =>
      step.system_id === observation.system_id && step.resource_id === observation.resource_id);
    const policySection = makeSection("POLICY RESULT / FUTURE WORK");
    if (resourceSteps.length) {
      for (const step of resourceSteps) {
        policySection.append(detailRow(`${step.phase} · ${step.state}`, `${step.operation} · evidence ${step.evidence_id || "not applicable to proposed work"}`));
      }
      if (resourceSteps.some((step) => step.phase === "REMEDIATION")) {
        policySection.append(makeDimCopy("Remediation is proposed only. No command was sent to the source system."));
      }
    } else {
      policySection.append(makeDimCopy("No policy step was generated for this observation."));
    }
    elements.drawerContent.append(policySection);
    elements.drawer.classList.add("is-open");
    elements.drawer.setAttribute("aria-hidden", "false");
    elements.closeDrawer.focus();
  }

  function makeSection(title) {
    const section = document.createElement("section");
    section.className = "drawer-section";
    const heading = document.createElement("h3");
    heading.textContent = title;
    section.append(heading);
    return section;
  }

  function addDrawerSection(title, rows) {
    const section = makeSection(title);
    for (const row of rows) section.append(detailRow(row[0], row[1]));
    elements.drawerContent.append(section);
  }

  function detailRow(label, value) {
    const row = document.createElement("div");
    row.className = "detail-row";
    const left = document.createElement("span");
    left.textContent = label;
    const right = document.createElement("span");
    right.textContent = value == null ? "—" : String(value);
    row.append(left, right);
    return row;
  }

  function renderGraph(serializedGraph, graphError, result) {
    elements.map.replaceChildren();
    elements.mapProvenance.replaceChildren();
    elements.map.setAttribute("viewBox", "0 0 540 180");
    elements.map.style.height = "112px";

    let graph = null;
    try {
      graph = typeof serializedGraph === "string" ? JSON.parse(serializedGraph) : serializedGraph;
    } catch (_error) {
      graph = null;
    }
    if (!graph || graph.schema_version !== "ghost-data-map.v1") {
      text(elements.mapCaption, graphError || "No cutoff-valid, evidence-backed graph payload is available.");
      elements.mapProvenance.append(makeDimCopy("Graph provenance is unavailable for this result."));
      return;
    }

    const nodes = Array.isArray(graph.nodes) ? graph.nodes : [];
    const edges = Array.isArray(graph.edges) ? graph.edges : [];
    const nodeById = new Map(nodes.map((node) => [node.node_id, node]));
    const systems = nodes.filter((node) => node.node_type === "SYSTEM");
    const resources = nodes.filter((node) => node.node_type === "RESOURCE");
    const positions = new Map();
    const placeRow = (items, y) => items.forEach((node, index) => {
      const x = items.length === 1 ? 270 : 36 + index * (468 / (items.length - 1));
      positions.set(node.node_id, { x, y });
    });
    if (systems.length && resources.length) {
      placeRow(systems, 38);
      placeRow(resources, 132);
    } else {
      const onlyNodes = systems.length ? systems : resources;
      onlyNodes.forEach((node, index) => {
        const x = onlyNodes.length === 1 ? 270 : 36 + index * (468 / (onlyNodes.length - 1));
        positions.set(node.node_id, { x, y: 84 });
      });
    }

    const defs = svgElement("defs", {});
    const marker = svgElement("marker", {
      id: "ghost-map-arrow", markerWidth: 6, markerHeight: 6,
      refX: 5, refY: 3, orient: "auto", markerUnits: "strokeWidth",
    });
    marker.append(svgElement("path", { d: "M0,0 L6,3 L0,6 z", class: "map-arrow" }));
    defs.append(marker);
    elements.map.append(defs);

    for (const edge of edges) {
      const from = positions.get(edge.source_node_id);
      const to = positions.get(edge.destination_node_id);
      if (!from || !to) continue;
      const line = svgElement("line", {
        x1: from.x, y1: from.y, x2: to.x, y2: to.y,
        class: `map-edge${edge.active_state === "ACTIVE" ? " is-active" : ""}${edge.support_status === "REPORTED_ACTIVITY" ? " is-claim" : ""}`,
      });
      if (edge.support_status !== "REPORTED_ACTIVITY") {
        line.setAttribute("marker-end", "url(#ghost-map-arrow)");
      }
      const title = svgElement("title", {});
      title.textContent = [
        edge.edge_type,
        `Relationship: ${edge.relationship_type || "not stated"}`,
        `${edge.source_node_id} → ${edge.destination_node_id}`,
        `Evidence: ${(edge.evidence_ids || []).join(", ") || "none"}`,
        `Trace IDs: ${(edge.trace_ids || []).join(", ") || "none"}`,
        `Locators: ${(edge.source_locators || []).join(", ") || "none"}`,
        `Record time: ${(edge.record_timestamps || []).map((item) => item.timestamp).join(", ") || "unknown"}`,
        `Captured: ${(edge.captured_at || []).map((item) => item.captured_at).join(", ") || "unknown"}`,
        `Audit cutoff: ${edge.audit_at || graph.audit_at}`,
        `Cutoff: ${edge.cutoff_status || "not stated"}`,
      ].join("\n");
      line.append(title);
      elements.map.append(line);
    }

    for (const node of nodes) {
      const point = positions.get(node.node_id);
      if (!point) continue;
      const active = node.visual_state === "ACTIVE_FLOW";
      const resource = node.node_type === "RESOURCE";
      const circle = svgElement("circle", {
        cx: point.x, cy: point.y, r: resource ? 5 : 4,
        class: `map-node${resource ? " map-node-resource" : ""}${active ? " is-active" : ""}`,
      });
      const provenance = (node.provenance || []).flatMap((item) => [
        ...(item.trace_ids || []).map((trace) => `trace ${trace}`),
        ...(item.source_locators || []).map((locator) => `source ${locator}`),
      ]);
      const title = svgElement("title", {});
      title.textContent = [
        node.node_type,
        node.system_id,
        node.resource_id || "",
        `State: ${node.observed_state}`,
        `Visual state: ${node.visual_state}`,
        `Evidence: ${(node.evidence_ids || []).join(", ") || "none"}`,
        ...provenance,
        `Audit cutoff: ${graph.audit_at}`,
      ].filter(Boolean).join("\n");
      circle.append(title);
      elements.map.append(circle);
      const label = node.resource_id || node.system_id;
      const labelY = point.y === 38 ? point.y - 9 : point.y + 13;
      elements.map.append(svgText(point.x, labelY, label, "map-node-label", "middle"));
      if (resource) {
        const subtitleY = point.y === 38 ? point.y + 17 : point.y + 25;
        elements.map.append(svgText(point.x, subtitleY, node.system_id, "map-node-sub", "middle"));
      }
      if (resource && result) {
        const observation = (result.observations || []).find((item) =>
          item.system_id === node.system_id && item.resource_id === node.resource_id);
        if (observation) {
          circle.style.cursor = "pointer";
          circle.addEventListener("click", () => openDrawer(observation, result));
          circle.addEventListener("keydown", (event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              openDrawer(observation, result);
            }
          });
          circle.setAttribute("tabindex", "0");
          circle.setAttribute("role", "button");
          circle.setAttribute("aria-label", `Open evidence for ${node.system_id} ${node.resource_id}`);
        }
      }
    }

    text(elements.mapCaption, `${nodes.length} evidence-backed nodes · ${edges.length} evidenced edges · audit cutoff ${formatTime(graph.audit_at)}${graphError ? " · graph warning" : ""}`);
    renderGraphProvenance(graph, nodeById);
  }

  function renderGraphProvenance(graph, nodeById) {
    const heading = document.createElement("p");
    heading.className = "map-provenance-cutoff";
    heading.textContent = `Audit cutoff: ${graph.audit_at}`;
    elements.mapProvenance.append(heading);
    for (const node of graph.nodes || []) {
      const item = document.createElement("div");
      item.className = "map-provenance-item";
      const name = document.createElement("strong");
      name.textContent = `${node.node_type} · ${node.system_id}${node.resource_id ? ` / ${node.resource_id}` : ""}`;
      const info = document.createElement("p");
      const prov = (node.provenance || []).map((entry) => [
        `evidence ${entry.evidence_id}`,
        `trace ${(entry.trace_ids || []).join(", ") || "none"}`,
        `source ${(entry.source_locators || []).join(", ") || "none"}`,
        `record ${(entry.record_timestamps || []).join(", ") || "unknown"}`,
        `captured ${entry.captured_at || "unknown"}`,
      ].join(" · "));
      info.textContent = `State ${node.observed_state} · ${(node.evidence_ids || []).join(", ") || "no evidence IDs"}${prov.length ? ` · ${prov.join(" | ")}` : ""}`;
      item.append(name, info);
      elements.mapProvenance.append(item);
    }
    for (const edge of graph.edges || []) {
      const item = document.createElement("div");
      item.className = "map-provenance-item map-provenance-edge";
      const name = document.createElement("strong");
      name.textContent = `${edge.edge_type} · ${nodeById.get(edge.source_node_id)?.resource_id || nodeById.get(edge.source_node_id)?.system_id || edge.source_node_id} → ${nodeById.get(edge.destination_node_id)?.resource_id || nodeById.get(edge.destination_node_id)?.system_id || edge.destination_node_id}`;
      const info = document.createElement("p");
      const records = (edge.record_timestamps || []).map((entry) => entry.timestamp).join(", ") || "unknown";
      const captures = (edge.captured_at || []).map((entry) => entry.captured_at).join(", ") || "unknown";
      info.textContent = [
        `evidence ${(edge.evidence_ids || []).join(", ") || "none"}`,
        `relationship ${edge.relationship_type || "not stated"}`,
        `trace ${(edge.trace_ids || []).join(", ") || "none"}`,
        `source ${(edge.source_locators || []).join(", ") || "none"}`,
        `record ${records}`,
        `captured ${captures}`,
        `audit ${edge.audit_at || graph.audit_at}`,
        `cutoff ${edge.cutoff_status || "not stated"}`,
        edge.support_status === "REPORTED_ACTIVITY" ? "reported activity claim only" : "",
      ].filter(Boolean).join(" · ");
      item.append(name, info);
      elements.mapProvenance.append(item);
    }
    for (const warning of graph.warnings || []) {
      const item = document.createElement("p");
      item.className = "map-provenance-warning";
      item.textContent = `${warning.code}: ${warning.resource_id}`;
      elements.mapProvenance.append(item);
    }
  }

  function svgElement(name, attributes) {
    const node = document.createElementNS("http://www.w3.org/2000/svg", name);
    for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
    return node;
  }

  function svgText(x, y, value, className, anchor = "start") {
    const node = svgElement("text", { x, y, class: className, "text-anchor": anchor });
    node.textContent = value == null ? "" : String(value);
    return node;
  }

  function resourcePoints(result) {
    const observations = (result?.observations || []).filter((item) => item.evidence_references?.length);
    const residual = residualKeys(result?.steps || []);
    const verified = verifiedKeys(result?.steps || []);
    return [...new Map(observations.map((item) => {
      const key = `${item.system_id}\u0000${item.resource_id}`;
      return [key, {
        key,
        resource_id: item.resource_id,
        residual: residual.has(key),
        verified: verified.has(key),
      }];
    })).values()];
  }

  function drawParticles(resources) {
    // Each observed resource seeds an even share of the visual shell. These
    // surface specks provide texture; the counter/cards report real resources.
    const flecksPerResource = resources.length
      ? Math.max(650, Math.min(1050, Math.floor(12000 / resources.length)))
      : 0;
    particles = resources.flatMap((resource, resourceIndex) => {
      const seed = hashString(resource.key);
      return Array.from({ length: flecksPerResource }, (_, index) => {
        const u = ((index * 0.61803398875 + (seed % 997) / 997) % 1) * Math.PI * 2;
        const v = ((index * 0.754877666 + ((seed >>> 5) % 991) / 991) % 1) * Math.PI * 2;
        const jitter = (((seed ^ Math.imul(index + 1, 2654435761)) >>> 0) % 1000) / 1000;
        const spread = Math.sin((seed % 104729) * .00013 + index * 78.233) * .5;
        const spread2 = Math.cos((seed % 65521) * .00019 + index * 39.731) * .5;
        return {
          ...resource,
          u,
          v,
          jitter,
          spread,
          spread2,
          phase: ((seed + index * 47) % 1000) / 1000 * Math.PI * 2,
          resourceIndex,
        };
      });
    });
  }

  function hashString(value) {
    let hash = 2166136261;
    for (let index = 0; index < value.length; index++) {
      hash ^= value.charCodeAt(index);
      hash = Math.imul(hash, 16777619);
    }
    return hash >>> 0;
  }

  function renderCanvas(now) {
    const canvas = $("#particle-field");
    const context = canvas.getContext("2d");
    if (!context) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const width = window.innerWidth;
    const height = window.innerHeight;
    if (canvas.width !== Math.floor(width * dpr) || canvas.height !== Math.floor(height * dpr)) {
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
    }
    context.setTransform(dpr, 0, 0, dpr, 0, 0);
    context.clearRect(0, 0, width, height);
    const stage = $(".center-stage").getBoundingClientRect();
    const centerX = stage.left + stage.width / 2;
    const centerY = stage.top + stage.height * .39;
    const radiusX = Math.min(stage.width * .46, 460);
    const radiusY = Math.min(stage.height * .38, 355);
    const sweepProgress = sweepUntil ? Math.max(0, Math.min(1, (now - sweepStarted) / (sweepUntil - sweepStarted))) : 0;
    if (sweepUntil) {
      const x = centerX - radiusX + sweepProgress * radiusX * 2;
      context.beginPath();
      context.moveTo(x, centerY - radiusY * 1.3);
      context.lineTo(x, centerY + radiusY * 1.3);
      context.strokeStyle = "rgba(235,235,235,.5)";
      context.lineWidth = 1;
      context.shadowBlur = 18;
      context.shadowColor = "rgba(235,235,235,.8)";
      context.stroke();
      context.shadowBlur = 0;
    }
    const time = reducedMotion.matches ? 0 : now * .0007;
    const rotation = time * .55;
    const yaw = rotation + Math.sin(time * .23) * .16;
    const tilt = -.38 + Math.sin(time * .31) * .22;
    const waveMajor = (u) => .73 + Math.sin(u * 3 + time * .42) * .095 + Math.sin(u * 7 - time * .31) * .052;
    const waveMinor = (u) => .26 + Math.sin(u * 5 + time * .27) * .045 + Math.sin(u * 9 - time * .18) * .018;
    const project = (u, v, major, minor) => {
      const ring = major + minor * Math.cos(v);
      const px = ring * Math.cos(u);
      const py = ring * Math.sin(u);
      const pz = minor * Math.sin(v);
      const xYaw = px * Math.cos(yaw) + pz * Math.sin(yaw);
      const zYaw = -px * Math.sin(yaw) + pz * Math.cos(yaw);
      const y3 = py * Math.cos(tilt) - zYaw * Math.sin(tilt);
      const z3 = py * Math.sin(tilt) + zYaw * Math.cos(tilt);
      const perspective = 1 / (1 + z3 * .34);
      return { x: centerX + xYaw * radiusX * perspective, y: centerY + y3 * radiusY * perspective, z: z3 };
    };
    // Closed outer and inner tracks are projected through the same moving 3D
    // transform as the shell, so their speed and perspective stay in sync.
    [0, Math.PI].forEach((v, track) => {
      context.beginPath();
      for (let index = 0; index <= 240; index++) {
        const u = index / 240 * Math.PI * 2;
        const point = project(u, v, waveMajor(u), waveMinor(u));
        if (index === 0) context.moveTo(point.x, point.y);
        else context.lineTo(point.x, point.y);
      }
      context.closePath();
      context.strokeStyle = track === 0 ? "rgba(235,235,235,.16)" : "rgba(200,200,200,.11)";
      context.lineWidth = 1;
      context.stroke();
    });
    for (const particle of particles) {
      const wobble = reducedMotion.matches ? 0 : Math.sin(time * 2 + particle.phase) * 3;
      const dispersedU = particle.u + particle.spread * .075;
      const major = waveMajor(dispersedU) + particle.spread * .14;
      const minor = waveMinor(dispersedU) + particle.spread2 * .12;
      const dispersedV = particle.v + particle.spread2 * .18;
      const projected = project(dispersedU, dispersedV, major, minor);
      let x = projected.x + wobble;
      let y = projected.y + wobble;
      const dx = x - pointer.x;
      const dy = y - pointer.y;
      const distance = Math.hypot(dx, dy);
      if (!reducedMotion.matches && distance < 85 && distance > 0) {
        const push = (85 - distance) / 85 * 17;
        x += dx / distance * push;
        y += dy / distance * push;
      }
      const focused = focusedResource && focusedResource.resource_id === particle.resource_id;
      const color = particle.residual ? "245,245,245" : particle.verified ? "205,205,205" : "145,145,145";
      const depthAlpha = .55 + Math.max(0, Math.min(1, (projected.z + 1) / 2)) * .45;
      const alpha = focused ? .98 : (particle.residual ? .9 : particle.verified ? .72 : .56) * depthAlpha;
      const radius = (focused ? 3.2 : 0.9 + particle.jitter * 1.45) * (.8 + depthAlpha * .3);
      context.beginPath();
      context.arc(x, y, radius, 0, Math.PI * 2);
      context.fillStyle = `rgba(${color},${alpha})`;
      context.shadowBlur = focused ? 8 : particle.jitter > .93 ? 3 : 0;
      context.shadowColor = `rgba(${color},${alpha * .6})`;
      context.fill();
      context.shadowBlur = 0;
    }
    requestAnimationFrame(renderCanvas);
  }

  function focusResource(observation) {
    focusedResource = observation;
  }

  function statusColor(status) {
    if (status === "COMPLETE") return "#c8c8c8";
    if (status === "INCOMPLETE") return "#f0f0f0";
    if (["AMBIGUOUS", "UNRESOLVED"].includes(status)) return "#a5a5a5";
    if (status === "NOT_APPLICABLE") return "var(--accent)";
    return "#5e5b66";
  }

  elements.caseSelect.addEventListener("change", () => {
    showCaseHeader(currentCase());
    runVerification();
  });
  elements.verifyButton.addEventListener("click", runVerification);
  elements.closeDrawer.addEventListener("click", closeDrawer);
  elements.drawer.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeDrawer();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeDrawer();
  });
  document.addEventListener("pointermove", (event) => {
    pointer = { x: event.clientX, y: event.clientY };
  }, { passive: true });

  function closeDrawer() {
    elements.drawer.classList.remove("is-open");
    elements.drawer.setAttribute("aria-hidden", "true");
  }

  window.matchMedia("(prefers-reduced-motion: reduce)").addEventListener?.("change", () => {
    if (reducedMotion.matches) finishSweep();
  });
  window.addEventListener("load", () => {
    requestAnimationFrame(renderCanvas);
    loadCases().catch((error) => {
      resetResult("SERVICE UNAVAILABLE", error.message, "UNRESOLVED");
      showToast("Could not load the local request catalog.");
    });
  });
})();
