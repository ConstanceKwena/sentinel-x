"use strict";

const $ = (selector) => document.querySelector(selector);
const severityOrder = ["Critical", "High", "Medium", "Low"];
let activeEventFilters = new URLSearchParams();
const API_BASE = (() => {
  const pageUrl = new URL(window.location.href);
  if (pageUrl.port === "5500") {
    pageUrl.port = "8000";
    pageUrl.pathname = "/";
    pageUrl.search = "";
    pageUrl.hash = "";
  }
  return pageUrl.origin;
})();
const api = {
  async get(path) {
    const response = await fetch(`${API_BASE}${path}`);
    if (!response.ok) throw new Error(await responseMessage(response));
    return response.json();
  },
  async send(path, method, body) {
    const response = await fetch(`${API_BASE}${path}`, {
      method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!response.ok) throw new Error(await responseMessage(response));
    return response.json();
  },
};

async function responseMessage(response) {
  try {
    const body = await response.json();
    return body.detail || `Request failed (${response.status})`;
  } catch {
    return `Request failed (${response.status})`;
  }
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? escapeHtml(value)
    : date.toLocaleString(undefined, {
      year: "numeric", month: "short", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
      timeZoneName: "short",
    });
}

function showToast(message, isError = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.toggle("error", isError);
  toast.classList.add("visible");
  window.clearTimeout(showToast.timeout);
  showToast.timeout = window.setTimeout(() => toast.classList.remove("visible"), 4200);
}

function renderSeverity(distribution) {
  const maximum = Math.max(1, ...severityOrder.map((severity) => distribution[severity] || 0));
  $("#severity-chart").innerHTML = severityOrder.map((severity) => {
    const count = distribution[severity] || 0;
    const width = count ? Math.max(4, (count / maximum) * 100) : 0;
    return `<div class="severity-row">
      <span>${severity}</span>
      <span class="severity-track"><span class="severity-fill ${severity.toLowerCase()}" style="display:block;width:${width}%"></span></span>
      <span class="severity-count">${count}</span>
    </div>`;
  }).join("");
}

function renderEvents(events) {
  const rows = $("#event-rows");
  if (!events.length) {
    rows.innerHTML = '<tr><td colspan="7" class="empty-state">No recorded events match this activity source and filter.</td></tr>';
    return;
  }
  rows.innerHTML = events.map((event) => `<tr>
    <td>${formatTime(event.received_at)}</td>
    <td class="event-type">${escapeHtml(event.description || eventLabel(event.event_type))}</td>
    <td>${escapeHtml(event.username)}</td>
    <td class="event-ip">${escapeHtml(event.source_ip)}</td>
    <td>${escapeHtml(event.source_application || "—")}</td>
    <td>${escapeHtml(originLabel(event.source_origin))}</td>
    <td><button class="detail-button" data-event-id="${escapeHtml(event.event_id)}">Investigate</button>
      ${event.detections.length ? `<span class="severity-pill ${escapeHtml(event.detections[0].severity)}">${escapeHtml(event.detections[0].rule_id)}</span>` : ""}
      ${event.currently_blocked ? '<span class="status-pill open">Blocked</span>' : ""}
    </td>
  </tr>`).join("");
  rows.querySelectorAll("[data-event-id]").forEach((button) => {
    button.addEventListener("click", () => openEvent(button.dataset.eventId));
  });
}

function originLabel(origin) {
  return ({
    connected_application: "Connected application",
    simulation: "Simulation",
    unknown: "Unknown",
  })[origin] || "Unknown";
}

function eventLabel(eventType) {
  return ({
    login_failed: "Failed login",
    login_success: "Successful login",
    privilege_change: "Privilege change",
    internal_discovery: "Internal discovery",
    outbound_transfer: "Outbound transfer",
  })[eventType] || eventType;
}

function renderIncidents(incidents) {
  const rows = $("#incident-rows");
  if (!incidents.length) {
    rows.innerHTML = '<tr><td colspan="6" class="empty-state">No incidents match these filters.</td></tr>';
    return;
  }
  rows.innerHTML = incidents.map((incident) => `<tr>
    <td>
      <button class="incident-link" data-incident-id="${escapeHtml(incident.incident_id)}" title="${escapeHtml(incident.title)}">${escapeHtml(incident.title)}</button>
      <span class="incident-id">${escapeHtml(incident.incident_id)}</span>
      <span class="incident-id">${escapeHtml(incident.rule_id || "Rule unknown")} · ${escapeHtml(incident.username || "Account unknown")} · ${escapeHtml(incident.source_ip || "Source unknown")}</span>
    </td>
    <td><span class="severity-pill ${incident.severity.toLowerCase()}">${escapeHtml(incident.severity)}</span></td>
    <td><span class="risk-value">${incident.risk_score}/100</span></td>
    <td><span class="status-pill ${incident.status.toLowerCase()}">${escapeHtml(incident.status)}</span></td>
    <td>${formatTime(incident.updated_at)}</td>
    <td><button class="detail-button" data-incident-id="${escapeHtml(incident.incident_id)}">Investigate</button></td>
  </tr>`).join("");
  rows.querySelectorAll("[data-incident-id]").forEach((button) => {
    button.addEventListener("click", () => openIncident(button.dataset.incidentId));
  });
}

function renderChains(chains) {
  const target = $("#chain-list");
  if (!chains.length) {
    target.innerHTML = '<div class="empty-state">No related attack sequences detected.</div>';
    return;
  }
  target.innerHTML = chains.slice(0, 3).map((chain) => `<article class="chain-item">
    <div class="chain-meta"><strong>${escapeHtml(chain.username)} · ${escapeHtml(chain.source_ip)}</strong><span>${formatTime(chain.detected_at)}</span></div>
    <div class="chain-stages">${chain.stages.map((stage, index) =>
      `${index ? '<span class="chain-arrow">→</span>' : ""}<span>${escapeHtml(stage)}</span>`
    ).join("")}</div>
    <div class="chain-timeline">${(chain.timeline || []).slice(0, 6).map((event) => `<span title="${escapeHtml(event.details || event.event_id)}">${escapeHtml(eventLabel(event.event_type))}<time>${formatTime(event.occurred_at)}</time></span>`).join("")}${chain.timeline && chain.timeline.length > 6 ? `<span class="timeline-more">+${chain.timeline.length - 6} events</span>` : ""}</div>
  </article>`).join("");
}

function renderDetections(detections) {
  const target = $("#detection-list");
  if (!detections.length) {
    target.innerHTML = '<div class="empty-state">No detection findings in the selected activity. A failed login alone is not classified as a confirmed attack.</div>';
    return;
  }
  target.innerHTML = detections.slice(0, 8).map((detection) => `<article class="application-item">
    <span class="severity-pill ${escapeHtml(detection.severity)}">${escapeHtml(detection.rule_id)} · ${escapeHtml(detection.severity)}</span>
    <strong>${escapeHtml(detection.description)}</strong>
    <span class="risk-value">Risk ${escapeHtml(detection.risk_score)}/100</span>
    <time>${formatTime(detection.detected_at)}</time>
  </article>`).join("");
}

function renderResponse(summary) {
  const applications = summary.connected_applications || [];
  $("#application-list").innerHTML = applications.length
    ? applications.map((application) => `<div class="application-item">
        <strong>${escapeHtml(application.application_id)}</strong>
        <span class="status-pill ${escapeHtml(application.status)}">${escapeHtml(application.status)}</span>
        <time>Last event ${formatTime(application.last_seen_at)}</time>
      </div>`).join("")
    : '<div class="empty-state">No connected applications have reported events.</div>';

  const blocks = summary.active_blocks || [];
  $("#block-rows").innerHTML = blocks.length
    ? blocks.map((block) => `<article class="application-item">
        <strong>${escapeHtml(block.source_ip)}</strong>
        <span>${escapeHtml(block.reason)}</span>
        <span class="status-pill connected">${escapeHtml(block.status || "active")}</span>
        <span>${escapeHtml(block.rule_id || "Rule unknown")}</span>
        ${block.incident_id ? `<span>${escapeHtml(block.incident_id)}</span>` : ""}
        <time>Created ${formatTime(block.blocked_at)} · Expires ${formatTime(block.expires_at)}</time>
      </article>`).join("")
    : '<div class="empty-state">No active source blocks for this view.</div>';

  const actions = summary.response_history || [];
  $("#response-history-rows").innerHTML = actions.length
    ? actions.map((action) => `<tr>
        <td>${escapeHtml(action.action.replaceAll("_", " "))}</td>
        <td class="event-ip">${escapeHtml(action.source_ip)}</td>
        <td>${escapeHtml(action.actor)}</td>
        <td>${formatTime(action.occurred_at)}</td>
        <td>${formatTime(action.expires_at)}</td>
      </tr>`).join("")
    : '<tr><td colspan="5" class="empty-state">No response actions recorded.</td></tr>';

  const policy = summary.response_policy;
  if (policy) {
    $("#response-policy-note").textContent = policy.enabled
      ? `Enabled: ${policy.failed_login_threshold} failed logins across ${policy.minimum_accounts} accounts in ${policy.window_minutes} minutes; blocks expire after ${policy.block_minutes} minutes. Demo application only.`
      : "Automatic blocking is disabled. No network traffic or firewall rules are changed.";
  }
}

async function loadIncidents() {
  const parameters = new URLSearchParams();
  if ($("#status-filter").value) parameters.set("status", $("#status-filter").value);
  if ($("#severity-filter").value) parameters.set("severity", $("#severity-filter").value);
  parameters.set("source_origin", $("#activity-origin").value);
  if (activeEventFilters.get("source_application")) {
    parameters.set("source_application", activeEventFilters.get("source_application"));
  }
  const result = await api.get(`/incidents?${parameters.toString()}`);
  renderIncidents(result.incidents);
}

async function loadEvents() {
  const parameters = new URLSearchParams(activeEventFilters);
  parameters.set("limit", "20");
  parameters.set("source_origin", $("#activity-origin").value);
  const result = await api.get(`/events?${parameters.toString()}`);
  renderEvents(result.events);
  return result.events;
}

async function refreshDashboard(showErrors = true) {
  try {
    const origin = $("#activity-origin").value;
    const summaryParameters = new URLSearchParams({ source_origin: origin });
    const incidentParameters = new URLSearchParams({ source_origin: origin });
    const sourceApplication = activeEventFilters.get("source_application");
    if (sourceApplication) {
      summaryParameters.set("source_application", sourceApplication);
      incidentParameters.set("source_application", sourceApplication);
    }
    if ($("#status-filter").value) incidentParameters.set("status", $("#status-filter").value);
    if ($("#severity-filter").value) incidentParameters.set("severity", $("#severity-filter").value);
    const [summary, incidents, chainResult] = await Promise.all([
      api.get(`/dashboard/summary?${summaryParameters.toString()}`),
      api.get(`/incidents?${incidentParameters.toString()}`),
      api.get(`/attack-chains?source_origin=${encodeURIComponent(origin)}${sourceApplication ? `&source_application=${encodeURIComponent(sourceApplication)}` : ""}`),
    ]);
    const events = await loadEvents();
    $("#total-events").textContent = summary.total_events.toLocaleString();
    $("#failed-logins").textContent = summary.failed_logins.toLocaleString();
    $("#successful-logins").textContent = summary.successful_logins.toLocaleString();
    $("#active-incidents").textContent = summary.active_incidents.toLocaleString();
    $("#critical-threats").textContent = summary.critical_threats.toLocaleString();
    $("#blocked-sources").textContent = summary.active_blocks.length.toLocaleString();
    $("#connected-app-count").textContent = summary.connected_applications
      .filter((application) => application.status === "connected").length.toLocaleString();
    $("#detection-count").textContent = summary.detection_count.toLocaleString();
    $("#nav-incident-count").textContent = String(summary.active_incidents);
    $("#updated-at").textContent = `UPDATED ${new Date().toLocaleTimeString()}`;
    $("#api-status").innerHTML = '<span class="pulse-dot"></span> API AVAILABLE';
    $("#event-view-description").textContent = `${originLabel(origin)} activity · newest first · ${events.length} shown`;
    renderSeverity(summary.severity_distribution);
    renderIncidents(incidents.incidents);
    renderChains(chainResult.chains);
    renderResponse(summary);
    renderDetections(summary.recent_detections);
  } catch (error) {
    $("#api-status").innerHTML = '<span class="pulse-dot status-offline"></span> API UNAVAILABLE';
    if (showErrors) showToast(`Could not load live dashboard data: ${error.message}`, true);
  }
}

async function openEvent(eventId) {
  try {
    const event = await api.get(`/events/${encodeURIComponent(eventId)}`);
    const findings = event.detections.length
      ? `<div class="evidence-list">${event.detections.map((detection) => `<div class="evidence-item">
          <strong>${escapeHtml(detection.rule_id)} · ${escapeHtml(detection.severity)} · Risk ${escapeHtml(detection.risk_score)}/100</strong>
          <small>${escapeHtml(detection.explanation)}</small>
        </div>`).join("")}</div>`
      : "<p>No detection rule is currently supported by this event.</p>";
    const incidents = event.incidents.length
      ? `<div class="evidence-list">${event.incidents.map((incident) => `<div class="evidence-item">
          <strong>${escapeHtml(incident.incident_id)} · ${escapeHtml(incident.status)}</strong>
          <span>${escapeHtml(incident.rule_id || "Rule not recorded")} · ${escapeHtml(incident.severity)} · Risk ${escapeHtml(incident.risk_score)}/100</span>
          <button class="detail-button" data-incident-id="${escapeHtml(incident.incident_id)}">Open incident</button>
        </div>`).join("")}</div>`
      : "<p>No incident is associated with this event.</p>";
    const related = event.related_authentication_events.length
      ? `<div class="evidence-list">${event.related_authentication_events.map((relatedEvent) => `<div class="evidence-item">
          <strong>${escapeHtml(relatedEvent.description)}</strong>
          <time>${formatTime(relatedEvent.received_at)}</time>
          <span>${escapeHtml(relatedEvent.source_application || "Unknown application")} · ${escapeHtml(originLabel(relatedEvent.source_origin))}</span>
          <code>${escapeHtml(relatedEvent.event_id)}</code>
        </div>`).join("")}</div>`
      : "<p>No related authentication events were recorded.</p>";
    const responses = event.response_actions.length
      ? `<div class="evidence-list">${event.response_actions.map((action) => `<div class="evidence-item">
          <strong>${escapeHtml(action.action.replaceAll("_", " "))}</strong>
          <time>${formatTime(action.occurred_at)}</time><small>${escapeHtml(action.reason)}</small>
        </div>`).join("")}</div>`
      : "<p>No response action is associated with this source IP.</p>";
    $("#event-dialog-title").textContent = event.description;
    $("#event-dialog-content").innerHTML = `
      <section class="dialog-section"><div class="dialog-stats">
        <span class="dialog-stat">${escapeHtml(event.event_type)}</span>
        <span class="dialog-stat">${escapeHtml(originLabel(event.source_origin))}</span>
        <span class="dialog-stat">${escapeHtml(event.source_application || "Application unknown")}</span>
        <span class="dialog-stat">${escapeHtml(event.event_id)}</span>
      </div></section>
      <section class="dialog-section"><h3>Observed event</h3>
        <p>${escapeHtml(event.description)}</p>
        <p>Timestamp: ${formatTime(event.received_at)} · Account: ${escapeHtml(event.username)} · Source: ${escapeHtml(event.source_ip)}</p>
        ${event.failure_reason ? `<p>Failure reason: ${escapeHtml(event.failure_reason)}</p>` : ""}
        ${event.details ? `<p>Details: ${escapeHtml(event.details)}</p>` : ""}
      </section>
      <section class="dialog-section"><h3>Related authentication timeline</h3>${related}</section>
      <section class="dialog-section"><h3>Detection findings</h3>${findings}</section>
      <section class="dialog-section"><h3>Related incidents</h3>${incidents}</section>
      <section class="dialog-section"><h3>Response actions</h3>${responses}
        <p>Current application-level block: ${event.currently_blocked ? "Active" : "Not active"}.</p>
      </section>`;
    $("#event-dialog").showModal();
    $("#event-dialog-content").querySelectorAll("[data-incident-id]").forEach((button) => {
      button.addEventListener("click", () => {
        $("#event-dialog").close();
        openIncident(button.dataset.incidentId);
      });
    });
  } catch (error) {
    showToast(`Could not load event details: ${error.message}`, true);
  }
}

async function openIncident(incidentId) {
  try {
    const incident = await api.get(`/incidents/${encodeURIComponent(incidentId)}`);
    $("#dialog-title").textContent = incident.title;
    const chain = incident.attack_chain;
    const evidence = incident.evidence.length
      ? `<div class="evidence-list">${incident.evidence.map((event) => `<div class="evidence-item">
          <strong>${escapeHtml(eventLabel(event.event_type))}</strong><time>${formatTime(event.received_at)}</time>
          <span>${escapeHtml(event.username)} · ${escapeHtml(event.source_ip)}</span>
          <small>${escapeHtml(event.details || "No additional event details")}</small>
          <code>${escapeHtml(event.event_id)}</code>
        </div>`).join("")}</div>`
      : '<p>No supporting event IDs were attached.</p>';
    const actions = incident.recommended_actions.length
      ? `<ul class="dialog-list">${incident.recommended_actions.map((action) => `<li>${escapeHtml(action)}</li>`).join("")}</ul>`
      : "<p>No response actions were recorded.</p>";
    const history = incident.history.length
      ? incident.history.map((entry) => `<div class="history-item">${escapeHtml(entry.previous_status || "New")} → ${escapeHtml(entry.new_status)}${entry.note ? ` · ${escapeHtml(entry.note)}` : ""}<time>${formatTime(entry.changed_at)}</time></div>`).join("")
      : '<p>No status history is available.</p>';
    $("#dialog-content").innerHTML = `
      <section class="dialog-section"><div class="dialog-stats">
        <span class="severity-pill ${incident.severity.toLowerCase()}">${escapeHtml(incident.severity)}</span>
        <span class="dialog-stat">RISK ${incident.risk_score}/100</span>
        <span class="dialog-stat">${escapeHtml(incident.status)}</span>
        <span class="dialog-stat">${escapeHtml(incident.incident_id)}</span>
      </div></section>
      <section class="dialog-section"><h3>What happened</h3><p>${escapeHtml(incident.description)}</p></section>
      <section class="dialog-section"><h3>Why it is suspicious</h3><p>${escapeHtml(incident.explanation)}</p></section>
      ${chain ? `<section class="dialog-section"><h3>Correlated attack chain</h3><p>${escapeHtml(chain.description)} · ${escapeHtml(chain.username)} · ${escapeHtml(chain.source_ip)}</p></section>` : ""}
      <section class="dialog-section"><h3>Supporting event IDs</h3>${evidence}</section>
      <section class="dialog-section"><h3>Recommended analyst actions</h3>${actions}</section>
      <section class="dialog-section"><h3>Status history</h3>${history}</section>
      <section class="dialog-section"><h3>Update status</h3>
        <div class="dialog-actions">
          <label class="sr-only" for="incident-status">New incident status</label>
          <select id="incident-status"><option ${incident.status === "Open" ? "selected" : ""}>Open</option><option ${incident.status === "Investigating" ? "selected" : ""}>Investigating</option><option ${incident.status === "Resolved" ? "selected" : ""}>Resolved</option></select>
          <button id="save-status" class="button button-primary">Save status</button>
        </div>
      </section>`;
    $("#incident-dialog").showModal();
    $("#save-status").addEventListener("click", async () => {
      const status = $("#incident-status").value;
      try {
        await api.send(`/incidents/${encodeURIComponent(incidentId)}`, "PATCH", { status });
        showToast(`Incident status updated to ${status}.`);
        await refreshDashboard();
        await openIncident(incidentId);
      } catch (error) {
        showToast(`Could not update incident: ${error.message}`, true);
      }
    });
  } catch (error) {
    showToast(`Could not load incident details: ${error.message}`, true);
  }
}

$("#simulate-button").addEventListener("click", async () => {
  const button = $("#simulate-button");
  const scenario = $("#simulation-scenario").value;
  button.disabled = true;
  button.textContent = "Running local simulation…";
  try {
    const result = await api.send("/simulation/run", "POST", { scenario });
    await refreshDashboard();
    const label = $("#simulation-scenario").selectedOptions[0].textContent;
    showToast(`${label} complete: ${result.event_count} synthetic events, ${result.detections.length} detections, ${result.incidents_created} incidents, ${result.attack_chains.length} correlated chains.`);
  } catch (error) {
    showToast(`Simulation failed: ${error.message}`, true);
  } finally {
    button.disabled = false;
    button.innerHTML = "<span>▶</span> Run safe simulation";
  }
});

$("#status-filter").addEventListener("change", () => loadIncidents().catch((error) => showToast(error.message, true)));
$("#severity-filter").addEventListener("change", () => loadIncidents().catch((error) => showToast(error.message, true)));
$("#event-filter-form").addEventListener("submit", (event) => {
  event.preventDefault();
  activeEventFilters = new URLSearchParams();
  const type = $("#event-type-filter").value;
  const username = $("#event-username-filter").value.trim();
  const sourceIp = $("#event-ip-filter").value.trim();
  const sourceApplication = $("#source-application-filter").value.trim();
  if (type) activeEventFilters.set("event_type", type);
  if (username) activeEventFilters.set("username", username);
  if (sourceIp) activeEventFilters.set("source_ip", sourceIp);
  if (sourceApplication) activeEventFilters.set("source_application", sourceApplication);
  refreshDashboard().catch((error) => showToast(`Could not filter events: ${error.message}`, true));
});
$("#activity-origin").addEventListener("change", () => refreshDashboard());
$("#dialog-close").addEventListener("click", () => $("#incident-dialog").close());
$("#event-dialog-close").addEventListener("click", () => $("#event-dialog").close());
$("#incident-dialog").addEventListener("click", (event) => {
  if (event.target === $("#incident-dialog")) $("#incident-dialog").close();
});
$("#event-dialog").addEventListener("click", (event) => {
  if (event.target === $("#event-dialog")) $("#event-dialog").close();
});

refreshDashboard();
window.setInterval(() => refreshDashboard(false), 5000);
