/**
 * S.H.A.D.E. — Frontend Single Page Application Logic
 * Role: Member 4 — Frontend & User Workflow
 * Communicates with FastAPI backend at /api/v1/
 */

const API_BASE = "/api/v1";

// Application State
const state = {
  token: sessionStorage.getItem("shade_jwt") || "",
  deviceId: localStorage.getItem("shade_device_id") || "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  ownerMobile: "9876543210",
  currentTab: "dashboard",
  vaultItems: [],
  exposures: [],
  cases: [],
  activeAuthChallenge: null,
  threatScore: 0,
};

// Headers helper
function getHeaders() {
  const headers = {
    "Content-Type": "application/json",
    "X-Device-Id": state.deviceId,
  };
  if (state.token) {
    headers["Authorization"] = `Bearer ${state.token}`;
  }
  return headers;
}

// Tab Switching
function switchTab(tabName) {
  state.currentTab = tabName;
  document.querySelectorAll(".nav-tab-btn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === tabName);
  });
  document.querySelectorAll(".tab-pane").forEach(pane => {
    pane.classList.toggle("active", pane.id === `tab-${tabName}`);
  });

  if (tabName === "vault") loadVault();
  if (tabName === "exposure") loadExposures();
  if (tabName === "cases") loadCases();
  if (tabName === "dashboard") refreshDashboard();
}

// Authentication / Auto-Login for Demo
async function ensureSession() {
  if (state.token) {
    try {
      const chk = await fetch(`${API_BASE}/auth/status`, { headers: getHeaders() });
      if (chk.ok) {
        updateStatusBadge(true);
        return true;
      }
    } catch (_) {}
  }

  try {
    // 1. First check if a session can be created directly (already registered owner)
    const directRes = await fetch(`${API_BASE}/session/create`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    if (directRes.ok) {
      const data = await directRes.json();
      state.token = data.access_token;
      sessionStorage.setItem("shade_jwt", state.token);
      updateStatusBadge(true);
      return true;
    }

    // 2. If not registered yet, perform full 4-step registration
    await fetch(`${API_BASE}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mobile_number: state.ownerMobile,
      }),
    });

    const verifyRes = await fetch(`${API_BASE}/auth/verify-otp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mobile_number: state.ownerMobile,
        otp_code: "000000",
      }),
    });

    if (verifyRes.ok) {
      const verifyData = await verifyRes.json();
      const bindRes = await fetch(`${API_BASE}/auth/bind-device`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          device_fingerprint_hash: state.deviceId,
          platform: "windows",
          verification_ticket: verifyData.verification_ticket,
        }),
      });

      if (bindRes.ok) {
        const sessRes = await fetch(`${API_BASE}/session/create`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
        });
        if (sessRes.ok) {
          const sessData = await sessRes.json();
          state.token = sessData.access_token;
          sessionStorage.setItem("shade_jwt", state.token);
          updateStatusBadge(true);
          return true;
        }
      }
    }
  } catch (err) {
    console.warn("Session auto-negotiation deferred:", err);
  }
  updateStatusBadge(false);
  return false;
}

function updateStatusBadge(online) {
  const pill = document.getElementById("device-status-pill");
  if (pill) {
    pill.innerHTML = online 
      ? `<span class="indicator-dot"></span> DEV-ENCRYPTED-NODE: BOUND`
      : `<span class="indicator-dot" style="background:#ff0055; box-shadow:none;"></span> OFFLINE`;
  }
}

// Dashboard Refresh
async function refreshDashboard() {
  await ensureSession();
  await Promise.all([loadVault(), loadExposures(), loadCases()]);

  // Update metrics
  document.getElementById("metric-vault-count").textContent = state.vaultItems.length;
  document.getElementById("metric-token-count").textContent = state.vaultItems.length;
  document.getElementById("metric-case-count").textContent = state.cases.length;

  // Compute highest threat score
  let maxScore = 0;
  let topLevel = "NONE";
  state.exposures.forEach(exp => {
    if (exp.risk_score && exp.risk_score > maxScore) {
      maxScore = exp.risk_score;
      topLevel = exp.risk_level || "CRITICAL";
    }
  });

  state.threatScore = maxScore;
  const threatGaugeValue = document.getElementById("threat-gauge-value");
  const threatGaugeBadge = document.getElementById("threat-gauge-badge");
  if (threatGaugeValue) threatGaugeValue.textContent = Math.round(maxScore);
  if (threatGaugeBadge) {
    threatGaugeBadge.textContent = topLevel;
    threatGaugeBadge.className = `badge badge-${topLevel.toLowerCase()}`;
  }
}

// Vault Operations
async function loadVault() {
  try {
    const res = await fetch(`${API_BASE}/vault/`, { headers: getHeaders() });
    if (res.ok) {
      const data = await res.json();
      state.vaultItems = data.items || (Array.isArray(data) ? data : []);
      renderVaultTable();
    }
  } catch (err) {
    console.error("Failed to load vault:", err);
  }
}

function renderVaultTable() {
  const tbody = document.getElementById("vault-table-body");
  if (!tbody) return;

  if (state.vaultItems.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-muted);">Vault is empty. Copy sensitive data in the Sandbox to tokenize.</td></tr>`;
    return;
  }

  tbody.innerHTML = state.vaultItems.map(item => `
    <tr>
      <td><span class="token-badge">${item.synthetic_token}</span></td>
      <td><span class="type-pill">${item.data_type}</span></td>
      <td style="font-family:var(--font-mono); color:var(--text-secondary);">${item.masked_metadata || '••••••••'}</td>
      <td style="color:var(--text-muted); font-size:0.75rem;">${new Date(item.created_at).toLocaleTimeString()}</td>
      <td>
        <button class="btn" onclick="openAuthModal('${item.id}', '${item.synthetic_token}')">Reveal Real</button>
        <button class="btn btn-danger" style="margin-left:0.5rem;" onclick="deleteVaultItem('${item.id}')">Delete</button>
      </td>
    </tr>
  `).join("");
}

// Authorize & Reveal Flow (Challenge -> Assertion -> Reveal)
async function openAuthModal(vaultId, token) {
  try {
    // 1. Request authorization gate
    const reqRes = await fetch(`${API_BASE}/authorization/request`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({
        synthetic_token: token,
        requesting_component: "S.H.A.D.E. Local UI",
        purpose_scope: "Owner interactive decryption request",
      }),
    });
    if (!reqRes.ok) {
      const err = await reqRes.json();
      alert("Authorization request error: " + (err.detail || err.message));
      return;
    }
    const authData = await reqRes.json();
    const authId = authData.authorization_id;

    // 2. Fetch cryptographic challenge
    const chalRes = await fetch(`${API_BASE}/authorization/challenge/${authId}`, {
      method: "POST",
      headers: getHeaders(),
    });
    const challengeData = await chalRes.json();

    state.activeAuthChallenge = {
      authId,
      vaultId,
      token,
      challengeId: challengeData.challenge_id,
      nonce: challengeData.nonce,
    };

    // Open Modal
    document.getElementById("auth-modal-token").textContent = token;
    document.getElementById("auth-modal-challenge").textContent = challengeData.nonce.slice(0, 16) + "...";
    document.getElementById("auth-modal-pin").value = "";
    document.getElementById("auth-modal").classList.add("active");
  } catch (err) {
    alert("Authorization challenge error: " + err.message);
  }
}

async function submitAuthAssertion() {
  if (!state.activeAuthChallenge) return;
  const pin = document.getElementById("auth-modal-pin").value;
  if (!pin) {
    alert("Please enter device PIN.");
    return;
  }

  try {
    // 3. Approve with PIN assertion
    const approveRes = await fetch(`${API_BASE}/authorization/approve/${state.activeAuthChallenge.authId}`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({
        auth_method: "PIN",
        challenge_id: state.activeAuthChallenge.challengeId,
        assertion: pin,
      }),
    });

    if (!approveRes.ok) {
      const err = await approveRes.json();
      alert("Authentication Denied: " + (err.detail || err.message || "Invalid PIN"));
      return;
    }

    // 4. Reveal real value using authenticated vault retrieve
    const revealRes = await fetch(
      `${API_BASE}/vault/retrieve?sensitive_value_id=${encodeURIComponent(state.activeAuthChallenge.vaultId)}&authorization_id=${encodeURIComponent(state.activeAuthChallenge.authId)}`,
      {
        method: "POST",
        headers: getHeaders(),
      }
    );

    if (revealRes.ok) {
      const realData = await revealRes.json();
      closeModal("auth-modal");
      // Display revealed secret modal with 10s auto-destruct
      showRevealedValueModal(realData.real_value, state.activeAuthChallenge.token);
    } else {
      alert("Failed to retrieve decrypted value.");
    }
  } catch (err) {
    alert("Authorization processing failed: " + err.message);
  }
}

function showRevealedValueModal(secret, token) {
  const modal = document.getElementById("reveal-secret-modal");
  const display = document.getElementById("reveal-secret-content");
  const timerDisplay = document.getElementById("reveal-timer");
  display.textContent = secret;
  modal.classList.add("active");

  let countdown = 10;
  timerDisplay.textContent = `${countdown}s`;
  const interval = setInterval(() => {
    countdown -= 1;
    if (countdown <= 0) {
      clearInterval(interval);
      display.textContent = "•••••••• [PURGED FROM SCREEN]";
      setTimeout(() => closeModal("reveal-secret-modal"), 1000);
    } else {
      timerDisplay.textContent = `${countdown}s`;
    }
  }, 1000);
}

async function deleteVaultItem(id) {
  if (!confirm("Permanently delete this sensitive item? Authorizations will be invalidated.")) return;
  try {
    const res = await fetch(`${API_BASE}/vault/${id}`, {
      method: "DELETE",
      headers: getHeaders(),
    });
    if (res.ok) {
      loadVault();
      refreshDashboard();
    }
  } catch (err) {
    alert("Deletion failed: " + err.message);
  }
}

// Sandbox Clipboard Interception Flow
async function simulateClipboardAction() {
  await ensureSession();
  const input = document.getElementById("sandbox-input").value;
  const outputBox = document.getElementById("sandbox-output");
  const statusBadge = document.getElementById("sandbox-status-badge");

  if (!input.trim()) {
    outputBox.textContent = "// Enter text to test DLP";
    return;
  }

  // Submit to clipboard DLP endpoint
  try {
    const res = await fetch(`${API_BASE}/clipboard/submit`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({
        content: input,
        detected_type: "AUTO_DETECT", // DLP engine evaluates
      }),
    });

    const data = await res.json();
    if (data.is_sensitive) {
      statusBadge.textContent = `PROTECTED: ${data.data_type} [${data.action}]`;
      statusBadge.className = "badge badge-critical";
      outputBox.innerHTML = `
[DLP INTERCEPTION TRIGGERED]
Original Content: [BLOCKED & ENCRYPTED IN LOCAL VAULT]
Detected Data Type: ${data.data_type}
Clipboard Transformed To Synthetic Token:
<b style="color:var(--accent-cyan); font-size:1.1rem;">${data.synthetic_token}</b>

Rule Enforced: Original secret NEVER leaves local host clipboard.
      `;
    } else {
      statusBadge.textContent = "PASSTHROUGH (CLEAN TEXT)";
      statusBadge.className = "badge badge-low";
      outputBox.innerHTML = `
[NORMAL TEXT PASSTHROUGH]
Text is not sensitive.
Clipboard unaltered:
"${input}"
      `;
    }
    loadVault();
    refreshDashboard();
  } catch (err) {
    outputBox.textContent = "Error executing clipboard simulation: " + err.message;
  }
}

// Exposure Search & Monitoring
async function loadExposures() {
  try {
    const res = await fetch(`${API_BASE}/exposure/`, { headers: getHeaders() });
    if (res.ok) {
      const data = await res.json();
      state.exposures = data.exposures || (Array.isArray(data) ? data : []);
      renderExposures();
    }
  } catch (err) {
    console.error("Failed to load exposures:", err);
  }
}

async function runManualExposureSearch() {
  await ensureSession();
  const query = document.getElementById("exposure-query-input").value || "test_breached_aadhaar";
  try {
    const res = await fetch(`${API_BASE}/exposure/search`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({
        search_type: "PASSWORD",
        search_value_hash: query,
      }),
    });
    if (res.ok) {
      await loadExposures();
      refreshDashboard();
    }
  } catch (err) {
    alert("Exposure search failed: " + err.message);
  }
}

async function runMonitoringScan() {
  await ensureSession();
  try {
    const res = await fetch(`${API_BASE}/exposure/monitor/run`, {
      method: "POST",
      headers: getHeaders(),
    });
    if (res.ok) {
      await loadExposures();
      refreshDashboard();
      alert("Monitoring cycle completed.");
    }
  } catch (err) {
    alert("Monitoring cycle failed: " + err.message);
  }
}

function renderExposures() {
  const container = document.getElementById("exposures-grid");
  if (!container) return;

  if (state.exposures.length === 0) {
    container.innerHTML = `<div style="grid-column:1/-1; text-align:center; color:var(--text-muted); padding:2rem;">No active exposures recorded. Use manual search or monitoring above.</div>`;
    return;
  }

  container.innerHTML = state.exposures.map(exp => `
    <div class="metric-card ${exp.risk_level === 'CRITICAL' ? 'red' : 'amber'}">
      <h3>${exp.organization || 'External Breach Source'}</h3>
      <div style="display:flex; justify-content:space-between; align-items:center; margin:0.5rem 0;">
        <span class="type-pill">${exp.data_type}</span>
        <span class="badge badge-${(exp.risk_level || 'medium').toLowerCase()}">${exp.risk_level || 'MEDIUM'} (${Math.round(exp.risk_score || 0)})</span>
      </div>
      <p style="font-size:0.8rem; color:var(--text-secondary); margin:0.5rem 0;"><b>Evidence:</b> ${exp.evidence_summary || 'Observed in public repository index.'}</p>
      <p style="font-size:0.75rem; color:var(--text-muted);"><b>Attribution:</b> ${exp.attribution_info || 'Unknown unauthorized actor'}</p>
      <button class="btn btn-primary" style="margin-top:1rem; width:100%;" onclick="openCaseFromExposure('${exp.id}', '${exp.organization}')">Open DPDP Case</button>
    </div>
  `).join("");
}

// Case & Erasure Lifecycle
async function loadCases() {
  try {
    const res = await fetch(`${API_BASE}/cases/`, { headers: getHeaders() });
    if (res.ok) {
      const data = await res.json();
      state.cases = data.cases || (Array.isArray(data) ? data : []);
      renderCases();
    }
  } catch (err) {
    console.error("Failed to load cases:", err);
  }
}

async function openCaseFromExposure(expId, org) {
  try {
    const res = await fetch(`${API_BASE}/cases/`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({
        exposure_id: expId,
        organization: org,
        data_type: "PASSWORD",
        affected_data_description: "Exposed Personal Credentials",
        evidence: "Verified breach telemetry from threat engine.",
      }),
    });
    if (res.ok) {
      switchTab("cases");
    }
  } catch (err) {
    alert("Failed to create case: " + err.message);
  }
}

function renderCases() {
  const container = document.getElementById("cases-list");
  if (!container) return;

  if (state.cases.length === 0) {
    container.innerHTML = `<div style="text-align:center; color:var(--text-muted); padding:2rem;">No active legal erasure cases.</div>`;
    return;
  }

  container.innerHTML = state.cases.map(c => `
    <div class="metric-card" style="margin-bottom:1rem;">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <h3 style="font-size:1.1rem; color:var(--text-primary);">${c.organization} [Case: ${c.id.slice(0,8)}]</h3>
        <span class="badge ${c.status === 'COMPLIED' ? 'badge-low' : 'badge-critical'}">${c.status}</span>
      </div>
      <p style="font-size:0.82rem; color:var(--text-secondary); margin:0.5rem 0;"><b>Affected Data:</b> ${c.data_type || 'Personal Identity Data'} | <b>Created:</b> ${new Date(c.created_at).toLocaleDateString()}</p>
      <div style="margin-top:0.8rem; display:flex; gap:0.5rem;">
        <button class="btn btn-primary" onclick="prepareErasureWorkflow('${c.id}', '${c.organization}')">Prepare Statutory Notice</button>
        <button class="btn" onclick="sendFollowUp('${c.id}')">Follow-up Check</button>
      </div>
    </div>
  `).join("");
}

// 3-Step DPDP Erasure Wizard: Prepare -> Review -> Send
async function prepareErasureWorkflow(caseId, org) {
  try {
    const safeOrg = (org || "organization").toLowerCase().replace(/[^a-z0-9]/g, "");
    const res = await fetch(`${API_BASE}/erasure/`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({
        case_id: caseId,
        dpo_email: `dpo@${safeOrg}.example`,
        request_body: `Statutory Notice under Section 12 of the Digital Personal Data Protection Act, 2023.\n\nTo Data Protection Officer, ${org}:\n\nWe hereby exercise the Right to Erasure under Section 12(1) and 12(2) of the DPDP Act 2023. You are statutorily required to erase all compromised personal records within 7 days.`,
      }),
    });
    const erasureData = await res.json();
    
    // Show Review modal
    document.getElementById("erasure-review-org").textContent = org;
    document.getElementById("erasure-review-text").textContent = erasureData.request_body;
    document.getElementById("erasure-modal-id").value = erasureData.id;
    document.getElementById("erasure-review-modal").classList.add("active");
  } catch (err) {
    alert("Failed to prepare notice: " + err.message);
  }
}

async function confirmSendErasure() {
  const erasureId = document.getElementById("erasure-modal-id").value;
  try {
    const res = await fetch(`${API_BASE}/erasure/${erasureId}/send`, {
      method: "POST",
      headers: getHeaders(),
    });
    if (res.ok) {
      closeModal("erasure-review-modal");
      alert("DPDP Section 12 Statutory Notice Dispatched. 7-day monitoring window active.");
      loadCases();
    }
  } catch (err) {
    alert("Send action failed: " + err.message);
  }
}

async function sendFollowUp(caseId) {
  try {
    const res = await fetch(`${API_BASE}/erasure/${caseId}/followup`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({
        follow_up_body: "Statutory Follow-up Notice: The 7-day DPDP Act Section 12 statutory timeline has elapsed.",
      }),
    });
    if (res.ok) {
      alert("Follow-up status recorded.");
      loadCases();
    }
  } catch (err) {
    alert("Follow-up failed: " + err.message);
  }
}

// Voice Simulation Chips
function triggerVoiceSimulation(phrase) {
  const log = document.getElementById("voice-hud-log");
  if (!log) return;

  log.innerHTML += `<div style="margin-bottom:0.5rem;"><b style="color:var(--accent-purple);">[USER SPEECH]:</b> "${phrase}"</div>`;

  if (phrase.includes("authorize") || phrase.includes("reveal")) {
    log.innerHTML += `<div style="color:var(--accent-red); margin-bottom:0.8rem;"><b>[POLICY BLOCKED]:</b> Voice authorization is strictly disallowed by security policy. Biometric/PIN assertion required.</div>`;
  } else if (phrase.includes("threat") || phrase.includes("risk")) {
    log.innerHTML += `<div style="color:var(--accent-green); margin-bottom:0.8rem;"><b>[SHADE SPEECH]:</b> "Exposome Threat Index is currently ${Math.round(state.threatScore)} out of 100."</div>`;
  } else if (phrase.includes("scan")) {
    runMonitoringScan();
    log.innerHTML += `<div style="color:var(--accent-cyan); margin-bottom:0.8rem;"><b>[SHADE SPEECH]:</b> "Dispatched background exposure monitoring scan."</div>`;
  }
  log.scrollTop = log.scrollHeight;
}

// Modal helper
function closeModal(id) {
  const m = document.getElementById(id);
  if (m) m.classList.remove("active");
}

// Initialize on page load
document.addEventListener("DOMContentLoaded", () => {
  ensureSession().then(() => {
    refreshDashboard();
  });
});
