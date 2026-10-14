/**
 * DNSRadar - Frontend Application Logic (Clean Light Mode)
 * Telemetry Dashboard, Threat Pattern Visualizations & Query Sandbox
 */

// State
let queriesCache = [];
let statsCache = null;
let currentFilterType = "ALL";
let currentMinScore = 0.0;
let refreshInterval = null;

// Clean Threat Color Scheme (Light Mode Optimized)
const THREAT_COLORS = {
  "Benign": "#16a34a",
  "DNS Tunneling": "#dc2626",
  "DGA (Algorithmically Generated)": "#d97706",
  "Fast-Flux / C2 Beacon": "#7c3aed",
  "Typosquatting / Brand Impersonation": "#db2777",
  "Suspicious High-Entropy": "#ea580c",
  "Structural Anomaly": "#2563eb"
};

// DOM Elements
const metricTotalQueries = document.getElementById("metricTotalQueries");
const metricAnomalies = document.getElementById("metricAnomalies");
const metricAnomalyRate = document.getElementById("metricAnomalyRate");
const metricTunnelingCount = document.getElementById("metricTunnelingCount");
const metricDgaCount = document.getElementById("metricDgaCount");

const dbStatusDot = document.getElementById("dbStatusDot");
const dbStatusText = document.getElementById("dbStatusText");
const btnOpenDbConfig = document.getElementById("btnOpenDbConfig");
const dbModalBackdrop = document.getElementById("dbModalBackdrop");
const btnCloseDbModal = document.getElementById("btnCloseDbModal");
const btnCancelDbModal = document.getElementById("btnCancelDbModal");
const btnSaveDbConfig = document.getElementById("btnSaveDbConfig");
const inputMongoUri = document.getElementById("inputMongoUri");
const modalDbMode = document.getElementById("modalDbMode");
const modalDbError = document.getElementById("modalDbError");

const btnSimulateTraffic = document.getElementById("btnSimulateTraffic");
const btnRefreshData = document.getElementById("btnRefreshData");
const btnClearData = document.getElementById("btnClearData");

const analyzeForm = document.getElementById("analyzeForm");
const inputDomain = document.getElementById("inputDomain");
const selectRecordType = document.getElementById("selectRecordType");
const inputClientIp = document.getElementById("inputClientIp");
const inputTtl = document.getElementById("inputTtl");

const sandboxResultBox = document.getElementById("sandboxResultBox");
const resDomain = document.getElementById("resDomain");
const resThreatBadge = document.getElementById("resThreatBadge");
const resAnomalyScore = document.getElementById("resAnomalyScore");
const resScoreBar = document.getElementById("resScoreBar");
const resFeaturesGrid = document.getElementById("resFeaturesGrid");
const resIndicatorsList = document.getElementById("resIndicatorsList");

const filterThreatType = document.getElementById("filterThreatType");
const filterMinScore = document.getElementById("filterMinScore");
const lblMinScore = document.getElementById("lblMinScore");
const queriesTableBody = document.getElementById("queriesTableBody");

const forensicsModalBackdrop = document.getElementById("forensicsModalBackdrop");
const btnCloseForensicsModal = document.getElementById("btnCloseForensicsModal");
const btnCloseForensicsBtn = document.getElementById("btnCloseForensicsBtn");
const forensicDomain = document.getElementById("forensicDomain");
const forensicMeta = document.getElementById("forensicMeta");
const forensicScore = document.getElementById("forensicScore");
const forensicIndicatorsList = document.getElementById("forensicIndicatorsList");
const forensicsFeatureTableBody = document.getElementById("forensicsFeatureTableBody");

const toastContainer = document.getElementById("toastContainer");

// Preset Chips
const presets = {
  presetDga: { domain: "xk9480vlz109ql.biz", type: "A" },
  presetTunnel: { domain: "a49bf10e82c730da4fbc81029e81.77c82a10b9910d82.tunnel-data.net", type: "TXT" },
  presetC2: { domain: "c2-beacon-f9a12.dark-mesh.io", type: "A" },
  presetPhish: { domain: "paypa1-security-verification.xyz", type: "A" },
  presetBenign: { domain: "api.github.com", type: "A" }
};

// ==========================================================================
// Initialization
// ==========================================================================
document.addEventListener("DOMContentLoaded", () => {
  initEventListeners();
  fetchDbStatus();
  refreshTelemetry();

  // Auto poll every 10 seconds for real-time live ingestion
  refreshInterval = setInterval(() => {
    refreshTelemetry(false);
  }, 10000);
});

function initEventListeners() {
  // Database Modal Handlers
  btnOpenDbConfig.addEventListener("click", () => {
    fetchDbStatus();
    dbModalBackdrop.style.display = "flex";
  });
  btnCloseDbModal.addEventListener("click", () => dbModalBackdrop.style.display = "none");
  btnCancelDbModal.addEventListener("click", () => dbModalBackdrop.style.display = "none");
  btnSaveDbConfig.addEventListener("click", handleSaveDbConfig);

  // Forensics Modal Handlers
  btnCloseForensicsModal.addEventListener("click", () => forensicsModalBackdrop.style.display = "none");
  btnCloseForensicsBtn.addEventListener("click", () => forensicsModalBackdrop.style.display = "none");

  // Actions
  btnSimulateTraffic.addEventListener("click", handleSimulateTraffic);
  btnRefreshData.addEventListener("click", () => {
    refreshTelemetry(true);
    showToast("Telemetry refreshed", "info");
  });
  btnClearData.addEventListener("click", handleClearData);

  // Filters
  filterThreatType.addEventListener("change", (e) => {
    currentFilterType = e.target.value;
    renderQueriesTable();
  });

  filterMinScore.addEventListener("input", (e) => {
    currentMinScore = parseFloat(e.target.value);
    lblMinScore.textContent = currentMinScore.toFixed(2);
    renderQueriesTable();
  });

  // Sandbox Form
  analyzeForm.addEventListener("submit", handleAnalyzeSubmit);

  // Presets
  Object.keys(presets).forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener("click", () => {
        inputDomain.value = presets[id].domain;
        selectRecordType.value = presets[id].type;
        handleAnalyzeSubmit(new Event("submit"));
      });
    }
  });
}

// ==========================================================================
// API Calls & Data Synchronization
// ==========================================================================
async function fetchDbStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    const db = data.database || {};
    
    if (db.is_mongo_connected) {
      dbStatusDot.className = "status-dot online";
      dbStatusText.textContent = "MongoDB Connected";
      modalDbMode.textContent = "Active Live MongoDB";
      modalDbError.textContent = "Healthy (Port 27017)";
    } else {
      dbStatusDot.className = "status-dot warning";
      dbStatusText.textContent = "Embedded Mock Store";
      modalDbMode.textContent = "Local File-Backed Mock Store";
      modalDbError.textContent = db.error ? "MongoDB offline; using local fallback store" : "Active";
    }
  } catch (err) {
    console.error("DB Status check failed:", err);
  }
}

async function handleSaveDbConfig() {
  const uri = inputMongoUri.value.trim();
  btnSaveDbConfig.textContent = "Connecting...";
  btnSaveDbConfig.disabled = true;

  try {
    const res = await fetch("/api/config/db", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ uri })
    });
    const data = await res.json();
    
    if (data.success) {
      showToast("Successfully connected to MongoDB!", "success");
    } else {
      showToast("Could not reach MongoDB. Active fallback retained.", "danger");
    }
    fetchDbStatus();
    dbModalBackdrop.style.display = "none";
  } catch (err) {
    showToast("Failed to connect to specified URI.", "danger");
  } finally {
    btnSaveDbConfig.textContent = "Test & Connect";
    btnSaveDbConfig.disabled = false;
  }
}

async function refreshTelemetry(showNotice = false) {
  try {
    const [statsRes, queriesRes] = await Promise.all([
      fetch("/api/stats"),
      fetch("/api/queries?limit=100")
    ]);

    statsCache = await statsRes.json();
    const queriesData = await queriesRes.json();
    queriesCache = queriesData.queries || [];

    updateMetricsView(statsCache);
    drawThreatBreakdownChart(statsCache.threat_breakdown || {});
    drawSeveritySpectrumChart(statsCache.score_distribution || {});
    renderQueriesTable();
  } catch (err) {
    console.error("Error fetching telemetry:", err);
  }
}

function updateMetricsView(stats) {
  if (!stats) return;

  metricTotalQueries.textContent = (stats.total_queries || 0).toLocaleString();
  metricAnomalies.textContent = (stats.anomalies_detected || 0).toLocaleString();
  metricAnomalyRate.textContent = `${stats.anomaly_rate || 0}% threshold hit`;

  const breakdown = stats.threat_breakdown || {};
  metricTunnelingCount.textContent = breakdown["DNS Tunneling"] || 0;
  metricDgaCount.textContent = (breakdown["DGA (Algorithmically Generated)"] || 0) + (breakdown["Fast-Flux / C2 Beacon"] || 0);
}

// ==========================================================================
// Sandbox Analyzer
// ==========================================================================
async function handleAnalyzeSubmit(e) {
  e.preventDefault();
  const domain = inputDomain.value.trim();
  if (!domain) return;

  const btn = document.getElementById("btnSubmitAnalyze");
  btn.disabled = true;
  btn.innerHTML = '<span class="btn-icon">⏳</span> Inspecting...';

  try {
    const payload = {
      domain: domain,
      record_type: selectRecordType.value,
      client_ip: inputClientIp.value.trim(),
      ttl: parseInt(inputTtl.value) || 300
    };

    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!res.ok) throw new Error("Analysis failed");
    const result = await res.json();

    displaySandboxResult(result);
    refreshTelemetry(false);
    showToast(`Evaluated: ${result.threat_type}`, result.is_anomaly ? "danger" : "success");
  } catch (err) {
    showToast("Error executing DNS inspection: " + err.message, "danger");
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span class="btn-icon">⚡</span> Analyze & Ingest Query';
  }
}

function displaySandboxResult(data) {
  sandboxResultBox.style.display = "block";
  resDomain.textContent = data.domain;

  const score = data.anomaly_score || 0;
  resAnomalyScore.textContent = score.toFixed(2);
  resScoreBar.style.width = `${Math.min(100, Math.round(score * 100))}%`;

  // Badge classification
  resThreatBadge.textContent = data.threat_type;
  if (score >= 0.70) {
    resThreatBadge.className = "result-threat-badge threat-badge-critical";
    resAnomalyScore.style.color = "var(--color-danger)";
  } else if (score >= 0.40) {
    resThreatBadge.className = "result-threat-badge threat-badge-medium";
    resAnomalyScore.style.color = "var(--color-warning)";
  } else {
    resThreatBadge.className = "result-threat-badge threat-badge-safe";
    resAnomalyScore.style.color = "var(--color-safe)";
  }

  // Feature metrics grid
  const feats = data.features || {};
  resFeaturesGrid.innerHTML = `
    <div class="f-metric-item">
      <div class="f-metric-lbl">Entropy</div>
      <div class="f-metric-val">${feats.entropy || 0} bits</div>
    </div>
    <div class="f-metric-item">
      <div class="f-metric-lbl">FQDN Length</div>
      <div class="f-metric-val">${feats.fqdn_length || 0} chars</div>
    </div>
    <div class="f-metric-item">
      <div class="f-metric-lbl">Hex Ratio</div>
      <div class="f-metric-val">${Math.round((feats.hex_ratio || 0) * 100)}%</div>
    </div>
    <div class="f-metric-item">
      <div class="f-metric-lbl">Vowel Ratio</div>
      <div class="f-metric-val">${Math.round((feats.vowel_ratio || 0) * 100)}%</div>
    </div>
    <div class="f-metric-item">
      <div class="f-metric-lbl">ML Decision</div>
      <div class="f-metric-val">${data.ml_score >= 0.5 ? "Outlier" : "Normal"}</div>
    </div>
  `;

  // Indicators list
  const indicators = data.indicators || [];
  resIndicatorsList.innerHTML = indicators.map(ind => `<li>${ind}</li>`).join("");
}

// ==========================================================================
// Simulation & Reset
// ==========================================================================
async function handleSimulateTraffic() {
  btnSimulateTraffic.disabled = true;
  btnSimulateTraffic.innerHTML = '<span class="btn-icon">⏳</span> Ingesting...';

  try {
    const res = await fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ count: 12, category: "random" })
    });
    const data = await res.json();
    showToast(data.message || "Simulated 12 queries.", "success");
    await refreshTelemetry(false);
  } catch (err) {
    showToast("Simulation failed: " + err.message, "danger");
  } finally {
    btnSimulateTraffic.disabled = false;
    btnSimulateTraffic.innerHTML = '<span class="btn-icon">⚡</span> Ingest Simulation Stream';
  }
}

async function handleClearData() {
  if (!confirm("Are you sure you want to clear all stored query telemetry?")) return;

  try {
    await fetch("/api/clear", { method: "POST" });
    showToast("Query telemetry wiped.", "info");
    refreshTelemetry(false);
  } catch (err) {
    showToast("Failed to clear data.", "danger");
  }
}

// ==========================================================================
// Query Table Rendering & Forensics Drill-Down
// ==========================================================================
function renderQueriesTable() {
  const filtered = queriesCache.filter(q => {
    const matchType = (currentFilterType === "ALL") || (q.threat_type === currentFilterType);
    const matchScore = (q.anomaly_score || 0) >= currentMinScore;
    return matchType && matchScore;
  });

  if (filtered.length === 0) {
    queriesTableBody.innerHTML = `
      <tr>
        <td colspan="8" class="table-empty">No DNS queries match the specified filter criteria.</td>
      </tr>
    `;
    return;
  }

  queriesTableBody.innerHTML = filtered.map((q, idx) => {
    const timeStr = formatTimestamp(q.timestamp);
    const score = (q.anomaly_score || 0).toFixed(2);
    const entropy = q.features ? q.features.entropy.toFixed(2) : "-";
    
    let scoreClass = "score-safe";
    if (score >= 0.70) scoreClass = "score-danger";
    else if (score >= 0.40) scoreClass = "score-medium";

    const color = THREAT_COLORS[q.threat_type] || "#2563eb";

    return `
      <tr>
        <td class="mono-cell" style="color: var(--text-secondary); font-size: 0.75rem;">${timeStr}</td>
        <td>
          <span class="domain-link" title="${q.domain}">${truncateString(q.domain, 38)}</span>
        </td>
        <td class="mono-cell"><span class="badge-tag">${q.record_type || "A"}</span></td>
        <td class="mono-cell" style="color: var(--text-secondary);">${q.client_ip || "192.168.1.1"}</td>
        <td class="mono-cell" style="color: var(--text-secondary);">${entropy}</td>
        <td>
          <span class="score-badge ${scoreClass}">${score}</span>
        </td>
        <td>
          <span style="display:inline-flex; align-items:center; gap: 0.35rem; color: ${color}; font-weight: 600; font-size: 0.75rem;">
            <span style="width: 7px; height: 7px; border-radius: 50%; background: ${color};"></span>
            ${q.threat_type}
          </span>
        </td>
        <td>
          <button class="btn-inspect" onclick="openForensicsModal(${idx})">Inspect</button>
        </td>
      </tr>
    `;
  }).join("");
}

window.openForensicsModal = function(index) {
  const q = queriesCache[index];
  if (!q) return;

  forensicDomain.textContent = q.domain;
  forensicMeta.textContent = `Client: ${q.client_ip || "192.168.1.1"} | Type: ${q.record_type || "A"} | TTL: ${q.ttl || 300}s | Time: ${q.timestamp}`;
  forensicScore.textContent = (q.anomaly_score || 0).toFixed(2);
  
  if (q.anomaly_score >= 0.7) {
    forensicScore.style.color = "var(--color-danger)";
  } else if (q.anomaly_score >= 0.4) {
    forensicScore.style.color = "var(--color-warning)";
  } else {
    forensicScore.style.color = "var(--color-safe)";
  }

  // Indicators
  const indicators = q.indicators || [];
  forensicIndicatorsList.innerHTML = indicators.map(ind => `<li>${ind}</li>`).join("");

  // Feature vector breakdown
  const feats = q.features || {};
  const featureDefinitions = [
    { name: "Shannon Entropy", val: `${feats.entropy || 0} bits`, base: "2.4 - 3.5 bits", threat: "Values > 3.8 indicate algorithmic generation (DGA) or encrypted payload." },
    { name: "FQDN Length", val: `${feats.fqdn_length || 0} bytes`, base: "12 - 32 bytes", threat: "Lengths > 50 bytes are hallmark signatures of DNS exfiltration channels." },
    { name: "Subdomain Depth", val: `${feats.subdomain_depth || 0} tiers`, base: "0 - 2 tiers", threat: "Deep hierarchy (>3 tiers) frequently used for fast-flux rotating domains." },
    { name: "Hexadecimal Density", val: `${Math.round((feats.hex_ratio || 0) * 100)}%`, base: "< 25%", threat: "Ratios > 60% indicate hex-encoded data chunks transported over DNS." },
    { name: "Vowel-to-Consonant Ratio", val: `${Math.round((feats.vowel_ratio || 0) * 100)}%`, base: "35% - 50%", threat: "Depleted vowel ratios (<18%) signal synthetic non-dictionary DGA text." },
    { name: "Consecutive Consonants", val: `${feats.consecutive_consonants || 0} chars`, base: "1 - 3 chars", threat: "Unbroken consonant clusters (5+) indicate high randomness." },
    { name: "Longest Label Length", val: `${feats.longest_label_len || 0} chars`, base: "4 - 15 chars", threat: "Labels approaching RFC max (63) represent high payload density." }
  ];

  forensicsFeatureTableBody.innerHTML = featureDefinitions.map(f => `
    <tr>
      <td style="font-weight: 600; color: var(--text-primary);">${f.name}</td>
      <td class="mono-cell" style="color: var(--primary-blue); font-weight: 600;">${f.val}</td>
      <td style="color: var(--text-muted);">${f.base}</td>
      <td style="color: var(--text-secondary); font-size: 0.74rem;">${f.threat}</td>
    </tr>
  `).join("");

  forensicsModalBackdrop.style.display = "flex";
};

// ==========================================================================
// Canvas Chart Renderers (Clean Light Mode)
// ==========================================================================
function drawThreatBreakdownChart(breakdown) {
  const canvas = document.getElementById("threatBreakdownCanvas");
  const legend = document.getElementById("threatBreakdownLegend");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  ctx.clearRect(0, 0, width, height);

  const entries = Object.entries(breakdown);
  const total = entries.reduce((acc, curr) => acc + curr[1], 0);

  if (total === 0) {
    ctx.fillStyle = "#94a3b8";
    ctx.font = "12px Inter, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("No threat telemetry recorded yet", width / 2, height / 2);
    legend.innerHTML = "";
    return;
  }

  const centerX = width / 2;
  const centerY = height / 2;
  const radius = Math.min(centerX, centerY) - 15;
  const innerRadius = radius * 0.58;

  let currentAngle = -Math.PI / 2;

  entries.forEach(([cat, count]) => {
    const sliceAngle = (count / total) * (Math.PI * 2);
    const color = THREAT_COLORS[cat] || "#64748b";

    // Donut slice
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, currentAngle, currentAngle + sliceAngle);
    ctx.arc(centerX, centerY, innerRadius, currentAngle + sliceAngle, currentAngle, true);
    ctx.closePath();
    ctx.fillStyle = color;
    ctx.fill();

    // Clean white border between slices
    ctx.strokeStyle = "#ffffff";
    ctx.lineWidth = 2.5;
    ctx.stroke();

    currentAngle += sliceAngle;
  });

  // Inner circle
  ctx.beginPath();
  ctx.arc(centerX, centerY, innerRadius, 0, Math.PI * 2);
  ctx.fillStyle = "#ffffff";
  ctx.fill();

  // Center counter
  ctx.fillStyle = "#0f172a";
  ctx.font = "bold 18px 'JetBrains Mono', monospace";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText(total.toString(), centerX, centerY - 7);

  ctx.fillStyle = "#64748b";
  ctx.font = "10px Inter, sans-serif";
  ctx.fillText("QUERIES", centerX, centerY + 11);

  // Render Legend
  legend.innerHTML = entries.map(([cat, count]) => {
    const color = THREAT_COLORS[cat] || "#64748b";
    const pct = Math.round((count / total) * 100);
    return `
      <div class="legend-item">
        <span class="legend-dot" style="background: ${color};"></span>
        <span>${cat}: <strong>${count}</strong> (${pct}%)</span>
      </div>
    `;
  }).join("");
}

function drawSeveritySpectrumChart(distribution) {
  const canvas = document.getElementById("severityCanvas");
  const legend = document.getElementById("severityLegend");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  ctx.clearRect(0, 0, width, height);

  const buckets = [
    { label: "Safe (<0.25)", key: "safe", color: "#16a34a" },
    { label: "Low (0.25-0.5)", key: "low", color: "#0284c7" },
    { label: "Medium (0.5-0.7)", key: "medium", color: "#d97706" },
    { label: "High (0.7-0.85)", key: "high", color: "#ea580c" },
    { label: "Critical (>0.85)", key: "critical", color: "#dc2626" }
  ];

  const values = buckets.map(b => distribution[b.key] || 0);
  const maxVal = Math.max(...values, 1);

  const barWidth = 36;
  const gap = (width - (barWidth * buckets.length)) / (buckets.length + 1);
  const chartBottom = height - 25;
  const maxBarHeight = height - 45;

  buckets.forEach((b, i) => {
    const val = distribution[b.key] || 0;
    const barHeight = (val / maxVal) * maxBarHeight;
    const x = gap + i * (barWidth + gap);
    const y = chartBottom - barHeight;

    // Track background
    ctx.fillStyle = "#f1f5f9";
    ctx.beginPath();
    ctx.roundRect ? ctx.roundRect(x, 15, barWidth, maxBarHeight, 3) : ctx.fillRect(x, 15, barWidth, maxBarHeight);
    ctx.fill();

    // Bar fill
    ctx.fillStyle = b.color;
    ctx.beginPath();
    ctx.roundRect ? ctx.roundRect(x, y, barWidth, barHeight, 3) : ctx.fillRect(x, y, barWidth, barHeight);
    ctx.fill();

    // Value text
    ctx.fillStyle = "#0f172a";
    ctx.font = "bold 11px 'JetBrains Mono', monospace";
    ctx.textAlign = "center";
    ctx.fillText(val.toString(), x + (barWidth / 2), Math.min(y - 5, chartBottom - 10));

    // X-axis label
    ctx.fillStyle = "#64748b";
    ctx.font = "9px Inter, sans-serif";
    ctx.fillText(b.key.toUpperCase(), x + (barWidth / 2), height - 8);
  });

  // Legend
  legend.innerHTML = buckets.map(b => `
    <div class="legend-item">
      <span class="legend-dot" style="background: ${b.color};"></span>
      <span>${b.label}</span>
    </div>
  `).join("");
}

// ==========================================================================
// Utilities
// ==========================================================================
function formatTimestamp(isoString) {
  if (!isoString) return "-";
  try {
    const date = new Date(isoString);
    return date.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return isoString.substring(11, 19);
  }
}

function truncateString(str, num) {
  if (!str) return "";
  if (str.length <= num) return str;
  return str.slice(0, num) + "...";
}

function showToast(message, type = "info") {
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${type === "danger" ? "⚠️" : type === "success" ? "✓" : "ℹ️"}</span> <span>${message}</span>`;
  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 250);
  }, 3500);
}
