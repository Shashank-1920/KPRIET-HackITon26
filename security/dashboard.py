"""
S.H.A.D.E. — Security, Threat Engine & Privacy Watchtower HUD
Design matched with Member 4 Frontend (Pure Clean Minimalist Design System).
"""

def get_dashboard_html() -> str:
    """Return the complete standalone HTML/CSS/JS dashboard matching Member 4 Frontend."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SHADE — Security & Threat Engine</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    /* =========================================================================
       PURE CLEAN MINIMALIST DESIGN SYSTEM (MATCHING MEMBER 4 FRONTEND)
       Apple & Vercel inspired: whitespace, crisp typography, zero visual noise
       ========================================================================= */
    :root {
      --bg: #09090b;
      --bg-subtle: #121215;
      --bg-hover: #18181b;
      --border: #27272a;
      --border-dark: #3f3f46;

      --text: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;

      --primary: #f8fafc;
      --primary-hover: #e2e8f0;
      --blue: #38bdf8;
      --blue-subtle: rgba(56, 189, 248, 0.1);
      --green: #34d399;
      --green-subtle: rgba(52, 211, 153, 0.1);
      --amber: #fbbf24;
      --amber-subtle: rgba(251, 191, 36, 0.1);
      --red: #f87171;
      --red-subtle: rgba(248, 113, 113, 0.1);

      --font: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      --mono: 'JetBrains Mono', ui-monospace, monospace;
      --radius: 8px;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: var(--font);
      font-size: 14px;
      line-height: 1.6;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      -webkit-font-smoothing: antialiased;
    }

    /* MINIMAL TOPBAR (MEMBER 4 NAVBAR SPEC) */
    header.nav-header {
      border-bottom: 1px solid var(--border);
      padding: 0 32px;
      height: 60px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: var(--bg);
      position: sticky;
      top: 0;
      z-index: 10;
    }

    .brand-wrap {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .brand-logo {
      font-weight: 700;
      font-size: 16px;
      letter-spacing: -0.5px;
      color: var(--text);
      text-decoration: none;
    }

    .brand-tag {
      font-size: 11px;
      color: var(--text-dim);
      font-family: var(--mono);
      background: var(--bg-subtle);
      border: 1px solid var(--border);
      padding: 2px 8px;
      border-radius: 20px;
    }

    nav.links-wrap {
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .tab-link {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 13px;
      font-weight: 500;
      padding: 6px 14px;
      border-radius: var(--radius);
      cursor: pointer;
      transition: all 0.15s ease;
      font-family: var(--font);
    }

    .tab-link:hover {
      color: var(--text);
      background: var(--bg-hover);
    }

    .tab-link.active {
      color: var(--text);
      background: var(--bg-hover);
      font-weight: 600;
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .status-badge {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 12px;
      color: var(--text-muted);
      font-family: var(--mono);
    }

    .dot-status {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--green);
      box-shadow: 0 0 6px var(--green);
    }

    .btn-minimal {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text);
      font-size: 12px;
      font-weight: 500;
      padding: 5px 12px;
      border-radius: var(--radius);
      cursor: pointer;
      transition: all 0.15s;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 4px;
    }

    .btn-minimal:hover {
      background: var(--bg-hover);
      border-color: var(--border-dark);
    }

    /* MAIN CONTAINER */
    main.container {
      max-width: 960px;
      width: 100%;
      margin: 0 auto;
      padding: 40px 24px 80px;
      flex: 1;
    }

    .tab-view {
      display: none;
    }

    .tab-view.active {
      display: block;
      animation: fadeIn 0.15s ease-out;
    }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(4px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .page-title {
      font-size: 22px;
      font-weight: 600;
      letter-spacing: -0.4px;
      margin-bottom: 6px;
    }

    .page-desc {
      font-size: 14px;
      color: var(--text-muted);
      margin-bottom: 28px;
    }

    /* CONTROLS & CHIPS */
    .chips-group {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 12px;
      flex-wrap: wrap;
    }

    .chips-label {
      font-size: 12px;
      color: var(--text-dim);
    }

    .chip-btn {
      background: var(--bg-subtle);
      border: 1px solid var(--border);
      color: var(--text-muted);
      font-size: 12px;
      padding: 4px 10px;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.15s;
    }

    .chip-btn:hover {
      background: var(--bg-hover);
      color: var(--text);
      border-color: var(--border-dark);
    }

    .editor-wrapper {
      position: relative;
      margin-bottom: 16px;
    }

    textarea.clean-input {
      width: 100%;
      background: var(--bg-subtle);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      color: var(--text);
      font-family: var(--mono);
      font-size: 13px;
      line-height: 1.6;
      padding: 16px;
      min-height: 120px;
      resize: vertical;
      outline: none;
      transition: border-color 0.15s;
    }

    textarea.clean-input:focus {
      border-color: var(--border-dark);
      background: var(--bg);
    }

    input.clean-input {
      width: 100%;
      background: var(--bg-subtle);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      color: var(--text);
      font-family: var(--mono);
      font-size: 13px;
      padding: 10px 14px;
      outline: none;
      transition: border-color 0.15s;
      margin-bottom: 12px;
    }

    input.clean-input:focus {
      border-color: var(--border-dark);
      background: var(--bg);
    }

    .action-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 32px;
    }

    .helper-text {
      font-size: 12px;
      color: var(--text-dim);
    }

    .btn-solid {
      background: var(--primary);
      color: #09090b;
      border: none;
      font-size: 13px;
      font-weight: 600;
      padding: 9px 18px;
      border-radius: var(--radius);
      cursor: pointer;
      transition: opacity 0.15s;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .btn-solid:hover {
      opacity: 0.9;
    }

    /* OUTPUT SPLIT & CARDS */
    .output-split {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-top: 20px;
    }

    @media (max-width: 680px) {
      .output-split {
        grid-template-columns: 1fr;
      }
    }

    .output-card {
      border: 1px solid var(--border);
      border-radius: var(--radius);
      background: var(--bg-subtle);
      padding: 18px;
      display: flex;
      flex-direction: column;
    }

    .output-card-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 12px;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--border);
    }

    .output-card-title {
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .output-box {
      font-family: var(--mono);
      font-size: 12.5px;
      line-height: 1.6;
      color: var(--text);
      white-space: pre-wrap;
      word-break: break-all;
    }

    /* PILLS (EXACT MEMBER 4 SPEC) */
    .pill-token {
      background: var(--blue-subtle);
      color: var(--blue);
      border: 1px solid var(--blue);
      font-family: var(--mono);
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 600;
    }

    .pill-real {
      background: var(--red-subtle);
      color: var(--red);
      border: 1px solid var(--red);
      font-family: var(--mono);
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 500;
    }

    /* SCORE BANNER (EXACT MEMBER 4 SPEC) */
    .score-banner {
      display: flex;
      align-items: baseline;
      gap: 12px;
      margin-bottom: 24px;
    }

    .big-score {
      font-size: 54px;
      font-weight: 800;
      letter-spacing: -2px;
      line-height: 1;
      font-family: var(--mono);
    }

    .score-unit {
      font-size: 18px;
      color: var(--text-dim);
    }

    .score-grade {
      font-size: 12px;
      font-weight: 600;
      padding: 3px 10px;
      border-radius: 20px;
    }

    .grade-allow { color: var(--green); background: var(--green-subtle); border: 1px solid var(--green); }
    .grade-gate { color: var(--amber); background: var(--amber-subtle); border: 1px solid var(--amber); }
    .grade-block { color: var(--red); background: var(--red-subtle); border: 1px solid var(--red); }

    /* SIMPLE LIST ROWS */
    .simple-list {
      display: flex;
      flex-direction: column;
      border: 1px solid var(--border);
      border-radius: var(--radius);
      background: var(--bg-subtle);
      overflow: hidden;
    }

    .list-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px 18px;
      border-bottom: 1px solid var(--border);
      font-size: 13px;
    }

    .list-row:last-child {
      border-bottom: none;
    }

    .list-row-left {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .list-impact {
      font-family: var(--mono);
      font-weight: 600;
      font-size: 12px;
    }

    /* FLOATING TOAST */
    .toast-pill {
      position: fixed;
      bottom: 24px;
      left: 50%;
      transform: translateX(-50%) translateY(40px);
      background: var(--bg-hover);
      border: 1px solid var(--border-dark);
      color: var(--text);
      font-size: 12px;
      font-weight: 500;
      padding: 8px 16px;
      border-radius: 20px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
      opacity: 0;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
      pointer-events: none;
      z-index: 1000;
    }

    .toast-pill.show {
      transform: translateX(-50%) translateY(0);
      opacity: 1;
    }

    /* FOOTER */
    footer.app-footer {
      border-top: 1px solid var(--border);
      padding: 24px 32px;
      text-align: center;
      font-size: 12px;
      color: var(--text-dim);
    }
  </style>
</head>
<body>
  <!-- HEADER -->
  <header class="nav-header">
    <div class="brand-wrap">
      <a href="#" class="brand-logo">SHADE</a>
      <span class="brand-tag">security-core</span>
    </div>

    <nav class="links-wrap">
      <button class="tab-link active" data-tab="tab-airlock">Prompt Airlock</button>
      <button class="tab-link" data-tab="tab-score">Threat Index</button>
      <button class="tab-link" data-tab="tab-breach">Breach Radar</button>
      <button class="tab-link" data-tab="tab-verhoeff">Verhoeff Tool</button>
      <button class="tab-link" data-tab="tab-canary">Canary Decoys</button>
      <button class="tab-link" data-tab="tab-dest">Destination Trust</button>
    </nav>

    <div class="header-actions">
      <div class="status-badge">
        <span class="dot-status"></span>
        <span>127.0.0.1:8000</span>
      </div>
      <a href="/docs" target="_blank" class="btn-minimal">API Docs</a>
    </div>
  </header>

  <!-- WORKSPACE -->
  <main class="container">

    <!-- ===================================================================
         TAB 1: TEST AI PRIVACY (AIRLOCK & DLP TOKENIZATION)
         =================================================================== -->
    <section class="tab-view active" id="tab-airlock">
      <h1 class="page-title">Prompt Privacy Airlock</h1>
      <p class="page-desc">Test real-time masking of Indian Aadhaar, PAN, UPI, Vehicle registration plates, and API secrets before payloads leave your host.</p>

      <div class="chips-group">
        <span class="chips-label">Quick samples:</span>
        <button class="chip-btn" id="load-sample-aadhaar">Aadhaar + PAN KYC</button>
        <button class="chip-btn" id="load-sample-keys">OpenAI + AWS Keys</button>
        <button class="chip-btn" id="load-sample-upi">UPI + Vehicle Plate</button>
        <button class="chip-btn" id="load-sample-clean">Clean Government Notice</button>
      </div>

      <div class="editor-wrapper">
        <textarea class="clean-input" id="airlock-input" placeholder="Type or paste prompt with sensitive data..."></textarea>
      </div>

      <div class="action-row">
        <span class="helper-text">Synthetic tokens generate 12-char SHA-256 derived keys (SHD_XXXXXXXX).</span>
        <button class="btn-solid" id="btn-protect-prompt">
          <span>Shield & Tokenize</span>
        </button>
      </div>

      <div class="output-split">
        <div class="output-card">
          <div class="output-card-head">
            <span class="output-card-title">What Cloud AI Sees (Synthetic Egress)</span>
            <span class="grade-gate score-grade" id="badge-count">0 items masked</span>
          </div>
          <div class="output-box" id="output-cloud">Prompt with intercepted sensitive data will appear here tokenized...</div>
        </div>

        <div class="output-card">
          <div class="output-card-head">
            <span class="output-card-title">What Stays On Device (Local Host Vault)</span>
            <span class="grade-allow score-grade">Zero Cloud Persistence</span>
          </div>
          <div class="output-box" id="output-local">Decrypted real values mapped exclusively in host memory...</div>
        </div>
      </div>
    </section>

    <!-- ===================================================================
         TAB 2: EXPOSOME THREAT INDEX (ETI SCORE & BREAKDOWN)
         =================================================================== -->
    <section class="tab-view" id="tab-score">
      <h1 class="page-title">Exposome Threat Index</h1>
      <p class="page-desc">Real-time composite risk calibration calculating outbound exposure hazard across identity, credentials, and destination risk.</p>

      <div class="score-banner">
        <span class="big-score" id="eti-display-score">0.0</span>
        <span class="score-unit">/ 100</span>
        <span class="score-grade grade-allow" id="eti-display-grade">INFO — ALLOW</span>
      </div>

      <div class="simple-list" id="eti-breakdown-list">
        <div class="list-row">
          <div class="list-row-left">
            <span>Identity PII (Aadhaar, PAN, Passport, Voter ID)</span>
          </div>
          <span class="list-impact" id="score-pii">+0.0</span>
        </div>

        <div class="list-row">
          <div class="list-row-left">
            <span>Critical Secrets (AWS, OpenAI, Slack, Private Keys)</span>
          </div>
          <span class="list-impact" id="score-secret">+0.0</span>
        </div>

        <div class="list-row">
          <div class="list-row-left">
            <span>Canary Honeytoken Breach (Active Exfiltration)</span>
          </div>
          <span class="list-impact" id="score-canary">+0.0</span>
        </div>

        <div class="list-row">
          <div class="list-row-left">
            <span>Destination Policy Penalty (Untrusted Public Egress)</span>
          </div>
          <span class="list-impact" id="score-dest">+0.0</span>
        </div>
      </div>
    </section>

    <!-- ===================================================================
         TAB 3: XPOSEDORNOT BREACH RADAR
         =================================================================== -->
    <section class="tab-view" id="tab-breach">
      <h1 class="page-title">Credential Breach Radar</h1>
      <p class="page-desc">Open-source intelligence powered by XposedOrNot. Privacy-preserving Keccak-512 k-anonymity verification.</p>

      <div style="margin-bottom: 24px;">
        <label style="display:block; font-size:12px; color:var(--text-dim); margin-bottom:6px; font-weight:600; text-transform:uppercase;">Candidate Password to Verify</label>
        <input type="text" class="clean-input" id="input-pwd" value="password" placeholder="Enter candidate password">
        <div class="chips-group">
          <button class="chip-btn" onclick="setTestPwd('password')">Common: 'password'</button>
          <button class="chip-btn" onclick="setTestPwd('123456')">Common: '123456'</button>
          <button class="chip-btn" onclick="setTestPwd('Sh@d3#2026!Secur1ty*Xyz')">Complex Unbreached</button>
        </div>
        <button class="btn-solid" id="btn-check-pwd" style="margin-top:8px;">Check Password Privacy</button>
      </div>

      <div class="output-card" style="margin-bottom: 32px;">
        <div class="output-card-head">
          <span class="output-card-title">Password k-Anonymity Result</span>
          <span class="grade-allow score-grade" id="badge-pwd-status">Ready</span>
        </div>
        <div class="output-box" id="box-pwd-res">Enter a password above to verify breach status with zero plaintext exposure.</div>
      </div>

      <div style="margin-bottom: 24px;">
        <label style="display:block; font-size:12px; color:var(--text-dim); margin-bottom:6px; font-weight:600; text-transform:uppercase;">Email Exposure Scanner</label>
        <input type="text" class="clean-input" id="input-email" value="test@example.com" placeholder="user@company.com">
        <button class="btn-solid" id="btn-check-email">Scan Email Breaches</button>
      </div>

      <div class="output-card">
        <div class="output-card-head">
          <span class="output-card-title">Email Exposure Dossier</span>
          <span class="grade-allow score-grade" id="badge-email-status">Ready</span>
        </div>
        <div class="output-box" id="box-email-res">Click Scan to query public incident archives.</div>
      </div>
    </section>

    <!-- ===================================================================
         TAB 4: AADHAAR VERHOEFF TOOL
         =================================================================== -->
    <section class="tab-view" id="tab-verhoeff">
      <h1 class="page-title">UIDAI Verhoeff Checksum Validator</h1>
      <p class="page-desc">Validates Indian 12-digit Aadhaar numbers against transposition errors using the dihedral group D5 checksum algorithm.</p>

      <div style="margin-bottom: 24px;">
        <input type="text" class="clean-input" id="input-verhoeff" value="266853339452" placeholder="Enter 12 digits">
        <div class="chips-group">
          <button class="chip-btn" onclick="setVerhoeffVal('266853339452')">Valid Aadhaar (266853339452)</button>
          <button class="chip-btn" onclick="setVerhoeffVal('266853339453')">Transposed (Invalid Checksum)</button>
          <button class="chip-btn" onclick="setVerhoeffVal('123456789012')">Arbitrary 12 Digits (Invalid)</button>
        </div>
        <button class="btn-solid" id="btn-run-verhoeff" style="margin-top:8px;">Validate Checksum</button>
      </div>

      <div class="output-card">
        <div class="output-card-head">
          <span class="output-card-title">Checksum Analysis</span>
          <span class="grade-allow score-grade" id="badge-verhoeff">Ready</span>
        </div>
        <div class="output-box" id="box-verhoeff">Click validate to run Dihedral D5 permutation matrix check.</div>
      </div>
    </section>

    <!-- ===================================================================
         TAB 5: CANARY HONEYTOKENS
         =================================================================== -->
    <section class="tab-view" id="tab-canary">
      <h1 class="page-title">Canary Honeytoken Manager</h1>
      <p class="page-desc">Mint trackable decoy credentials. Observing an active canary in external egress forces a catastrophic threat score and instant block.</p>

      <div style="margin-bottom: 24px;">
        <div class="chips-group">
          <button class="chip-btn" id="btn-mint-key">Mint Decoy API Key</button>
          <button class="chip-btn" id="btn-mint-email">Mint Decoy Email</button>
        </div>
      </div>

      <div class="output-card" style="margin-bottom: 32px;">
        <div class="output-card-head">
          <span class="output-card-title">Active Decoy Honeytoken</span>
          <span class="grade-allow score-grade" id="badge-canary-mint">Registered</span>
        </div>
        <div class="output-box" id="box-canary-mint">Click one of the buttons above to mint a canary.</div>
      </div>

      <div style="margin-bottom: 24px;">
        <label style="display:block; font-size:12px; color:var(--text-dim); margin-bottom:6px; font-weight:600; text-transform:uppercase;">Exfiltration Leak Scanner</label>
        <textarea class="clean-input" id="input-canary-scan" placeholder="Paste suspected exfiltrated payload or logs here..."></textarea>
        <button class="btn-solid" id="btn-scan-canary" style="margin-top:8px;">Scan for Canary Leaks</button>
      </div>

      <div class="output-card">
        <div class="output-card-head">
          <span class="output-card-title">Canary Exfiltration Alert</span>
          <span class="grade-allow score-grade" id="badge-canary-scan">Clean</span>
        </div>
        <div class="output-box" id="box-canary-scan">Scan results will appear here.</div>
      </div>
    </section>

    <!-- ===================================================================
         TAB 6: DESTINATION TRUST
         =================================================================== -->
    <section class="tab-view" id="tab-dest">
      <h1 class="page-title">Trusted Destination Policy</h1>
      <p class="page-desc">Strict allowlist policy evaluator verifying official Indian government (*.gov.in, *.nic.in) and accredited academic portals (*.ac.in, *.edu).</p>

      <div style="margin-bottom: 24px;">
        <input type="text" class="clean-input" id="input-dest" value="https://uidai.gov.in/verify" placeholder="https://domain.tld">
        <div class="chips-group">
          <button class="chip-btn" onclick="setDestVal('https://uidai.gov.in/verify')">UIDAI (Trusted Gov)</button>
          <button class="chip-btn" onclick="setDestVal('https://kpriet.ac.in/portal')">KPRIET (Trusted Academic)</button>
          <button class="chip-btn" onclick="setDestVal('https://evilgov.in')">evilgov.in (Spoof Attempt)</button>
          <button class="chip-btn" onclick="setDestVal('https://pastebin.com/api')">pastebin.com (Untrusted Public)</button>
        </div>
        <button class="btn-solid" id="btn-eval-dest" style="margin-top:8px;">Evaluate Destination Trust</button>
      </div>

      <div class="output-card">
        <div class="output-card-head">
          <span class="output-card-title">Domain Trust Dossier</span>
          <span class="grade-allow score-grade" id="badge-dest">Ready</span>
        </div>
        <div class="output-box" id="box-dest">Enter destination URL to inspect.</div>
      </div>
    </section>

  </main>

  <!-- TOAST -->
  <div class="toast-pill" id="toast-pill">Ready</div>

  <!-- FOOTER -->
  <footer class="app-footer">
    S.H.A.D.E. • Sovereign Host for AI Data Enforcement • Member 2 Security & Threat Engine
  </footer>

  <script>
    class ShadeHUD {
      constructor() {
        this.bindNav();
        this.bindAirlock();
        this.bindBreach();
        this.bindVerhoeff();
        this.bindCanary();
        this.bindDest();
      }

      toast(msg) {
        const t = document.getElementById('toast-pill');
        t.textContent = msg;
        t.classList.add('show');
        setTimeout(() => t.classList.remove('show'), 2200);
      }

      bindNav() {
        const links = document.querySelectorAll('.tab-link');
        const views = document.querySelectorAll('.tab-view');

        links.forEach(btn => {
          btn.addEventListener('click', () => {
            links.forEach(l => l.classList.remove('active'));
            views.forEach(v => v.classList.remove('active'));

            btn.classList.add('active');
            const target = btn.getAttribute('data-tab');
            document.getElementById(target).classList.add('active');
          });
        });
      }

      bindAirlock() {
        const input = document.getElementById('airlock-input');
        const btnProtect = document.getElementById('btn-protect-prompt');
        const cloudView = document.getElementById('output-cloud');
        const localView = document.getElementById('output-local');
        const badgeCount = document.getElementById('badge-count');

        const samples = {
          aadhaar: `Verify customer identity record for applicant Aarav Sharma:
UIDAI Aadhaar: 2668 5333 9452 (Verified Dihedral D5 Checksum)
Income Tax PAN Card: ABCDE1234F
Check retail banking risk eligibility.`,
          keys: `# Cloud Infrastructure Script
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
SLACK_BOT_TOKEN = "xoxb-YOUR-SLACK-BOT-TOKEN-HERE"`,
          upi: `Dispatch driver for fleet plate TN01AB1234.
Disburse fuel stipend to beneficiary UPI: alice@okhdfcbank
Awaiting partner acknowledgement.`,
          clean: `UIDAI compliance quarterly summary:
All data handling protocols verified against Section 12 of the DPDP Act 2023. Zero identity data exposed.`
        };

        document.getElementById('load-sample-aadhaar').addEventListener('click', () => {
          input.value = samples.aadhaar;
          this.toast('Loaded Aadhaar + PAN KYC sample');
        });
        document.getElementById('load-sample-keys').addEventListener('click', () => {
          input.value = samples.keys;
          this.toast('Loaded API keys sample');
        });
        document.getElementById('load-sample-upi').addEventListener('click', () => {
          input.value = samples.upi;
          this.toast('Loaded UPI + Vehicle Plate sample');
        });
        document.getElementById('load-sample-clean').addEventListener('click', () => {
          input.value = samples.clean;
          this.toast('Loaded clean government report');
        });

        btnProtect.addEventListener('click', async () => {
          const text = input.value.trim();
          if (!text) return;

          try {
            const res = await fetch('/api/v1/security/evaluate', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ text: text })
            });
            const data = await res.json();

            // Cloud View: highlight tokens
            let tokenizedHtml = data.tokenized_text || '';
            tokenizedHtml = tokenizedHtml.replace(/(SHD_[0-9A-F]{8})/g, '<span class="pill-token">$1</span>');
            cloudView.innerHTML = tokenizedHtml;

            // Local Vault view
            if (data.threats && data.threats.length > 0) {
              const summaryList = data.threats.map(t => `<div style="margin-bottom:6px;">• <span class="pill-real">${t.masked_evidence}</span> (${t.threat_type} — ${t.severity})</div>`).join('');
              localView.innerHTML = summaryList;
            } else {
              localView.innerHTML = `<span style="color:var(--green)">✓ Clean prompt. Zero sensitive credentials detected.</span>`;
            }

            const count = (data.threats || []).length;
            badgeCount.textContent = `${count} secret(s) masked`;
            badgeCount.className = count > 0 ? 'score-grade grade-gate' : 'score-grade grade-allow';

            // Update Exposure Score Tab simultaneously
            this.updateETIScore(data);

            this.toast(`Protected ${count} sensitive credential(s)`);
          } catch (err) {
            alert('Evaluation failed: ' + err);
          }
        });

        // Preload sample
        document.getElementById('load-sample-aadhaar').click();
      }

      updateETIScore(data) {
        const score = data.risk_assessment.exposome_threat_index;
        const sev = data.risk_assessment.severity;
        const act = data.risk_assessment.action_required;

        document.getElementById('eti-display-score').textContent = score.toFixed(1);

        const gradeEl = document.getElementById('eti-display-grade');
        gradeEl.textContent = `${sev} — ${act}`;
        if (sev === 'CRITICAL' || sev === 'HIGH' || act === 'BLOCK') {
          gradeEl.className = 'score-grade grade-block';
        } else if (sev === 'MEDIUM' || act === 'TOKENIZE_AND_GATE') {
          gradeEl.className = 'score-grade grade-gate';
        } else {
          gradeEl.className = 'score-grade grade-allow';
        }

        // Breakdown scores
        const bd = data.risk_assessment.breakdown;
        document.getElementById('score-pii').textContent = `+${bd.pii_score.toFixed(1)}`;
        document.getElementById('score-secret').textContent = `+${bd.secret_score.toFixed(1)}`;
        document.getElementById('score-canary').textContent = `+${bd.canary_score.toFixed(1)}`;
        document.getElementById('score-dest').textContent = `+${bd.destination_score.toFixed(1)}`;
      }

      bindBreach() {
        document.getElementById('btn-check-pwd').addEventListener('click', async () => {
          const pwd = document.getElementById('input-pwd').value;
          const box = document.getElementById('box-pwd-res');
          const badge = document.getElementById('badge-pwd-status');
          box.innerHTML = '<span style="color:var(--blue)">Querying XposedOrNot via k-anonymity...</span>';

          try {
            const res = await fetch('/api/v1/security/breach-radar/password', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ password: pwd })
            });
            const d = await res.json();

            if (d.is_breached) {
              badge.textContent = 'Exposed';
              badge.className = 'score-grade grade-block';
              box.innerHTML = `
                <div style="color:var(--red); font-weight:600; margin-bottom:6px;">⚠️ BREACH DETECTED IN KNOWN ARCHIVES</div>
                <div><strong>Breach Count:</strong> <span style="color:var(--red); font-weight:600;">${d.breach_count.toLocaleString()}</span> compromised instances</div>
                <div><strong>Hash Prefix (10-char Keccak):</strong> <code>${d.hash_prefix}</code></div>
                <div><strong>Verified Via:</strong> ${d.checked_via}</div>
                <div style="margin-top:8px; font-size:11px; color:var(--text-dim);">Zero-Knowledge Guarantee: Full password was never transmitted over the network.</div>
              `;
            } else {
              badge.textContent = 'Clean';
              badge.className = 'score-grade grade-allow';
              box.innerHTML = `
                <div style="color:var(--green); font-weight:600; margin-bottom:6px;">✓ PASSWORD CLEAN</div>
                <div>No matching hash prefix located in XposedOrNot database.</div>
                <div><strong>Hash Prefix (10-char):</strong> <code>${d.hash_prefix}</code></div>
              `;
            }
            this.toast('Password checked privately');
          } catch (err) {
            box.textContent = 'Error: ' + err;
          }
        });

        document.getElementById('btn-check-email').addEventListener('click', async () => {
          const email = document.getElementById('input-email').value;
          const box = document.getElementById('box-email-res');
          const badge = document.getElementById('badge-email-status');
          box.innerHTML = '<span style="color:var(--blue)">Scanning XposedOrNot archives...</span>';

          try {
            const res = await fetch('/api/v1/security/breach-radar/email', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ email: email })
            });
            const d = await res.json();

            if (d.is_breached) {
              badge.textContent = `${d.breaches_count} Breaches`;
              badge.className = 'score-grade grade-gate';
              const pills = (d.breaches || []).slice(0, 12).map(b => `<span class="pill-token" style="margin:2px;">${b}</span>`).join(' ');
              box.innerHTML = `
                <div style="color:var(--amber); font-weight:600; margin-bottom:6px;">⚠️ EMAIL COMPROMISED IN ${d.breaches_count} BREACHES</div>
                <div style="margin-top:6px; display:flex; flex-wrap:wrap; gap:4px;">${pills}</div>
              `;
            } else {
              badge.textContent = 'Zero Breaches';
              badge.className = 'score-grade grade-allow';
              box.innerHTML = `<span style="color:var(--green)">✓ Email clean. 0 exposures observed in public dumps.</span>`;
            }
            this.toast('Email breach scan complete');
          } catch (err) {
            box.textContent = 'Error: ' + err;
          }
        });
      }

      bindVerhoeff() {
        document.getElementById('btn-run-verhoeff').addEventListener('click', async () => {
          const num = document.getElementById('input-verhoeff').value;
          const box = document.getElementById('box-verhoeff');
          const badge = document.getElementById('badge-verhoeff');

          try {
            const res = await fetch('/api/v1/security/validators/verhoeff', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ number: num })
            });
            const d = await res.json();

            badge.textContent = d.is_valid_verhoeff ? 'Valid' : 'Invalid';
            badge.className = d.is_valid_verhoeff ? 'score-grade grade-allow' : 'score-grade grade-block';

            box.innerHTML = `
              <div><strong>Input:</strong> <code>${d.input}</code></div>
              <div><strong>Verhoeff Dihedral D5 Checksum:</strong> <span style="color:${d.is_valid_verhoeff ? 'var(--green)' : 'var(--red)'}; font-weight:600;">${d.is_valid_verhoeff ? 'VALID' : 'INVALID'}</span></div>
              <div><strong>UIDAI Aadhaar Compliant:</strong> <span style="color:${d.is_valid_aadhaar ? 'var(--green)' : 'var(--red)'}; font-weight:600;">${d.is_valid_aadhaar ? 'YES (12 digits passed)' : 'NO'}</span></div>
              <div><strong>Calculated Check Digit:</strong> <code>${d.calculated_check_digit !== null ? d.calculated_check_digit : 'N/A'}</code></div>
            `;
            this.toast('Verhoeff check finished');
          } catch (err) {
            box.textContent = 'Error: ' + err;
          }
        });
      }

      bindCanary() {
        let activeCanary = '';

        const mint = async (kind) => {
          const box = document.getElementById('box-canary-mint');
          try {
            const res = await fetch('/api/v1/security/canary/generate', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ kind: kind, attribution_tag: 'system_prompt_canary' })
            });
            const d = await res.json();
            activeCanary = d.value;
            box.innerHTML = `
              <div><strong>Decoy Value:</strong> <span class="pill-token">${d.value}</span></div>
              <div><strong>Attribution Tag:</strong> <code>${d.attribution_tag}</code></div>
              <div><strong>Status:</strong> ${d.status}</div>
              <div style="margin-top:8px;"><button class="chip-btn" id="copy-to-leak">Paste into Leak Scanner</button></div>
            `;
            document.getElementById('copy-to-leak').addEventListener('click', () => {
              document.getElementById('input-canary-scan').value = `Internal exfiltration log: ${activeCanary}`;
              this.toast('Copied canary to leak scanner');
            });
            this.toast(`Minted canary ${kind}`);
          } catch (err) {
            box.textContent = 'Error: ' + err;
          }
        };

        document.getElementById('btn-mint-key').addEventListener('click', () => mint('api_key'));
        document.getElementById('btn-mint-email').addEventListener('click', () => mint('email'));

        document.getElementById('btn-scan-canary').addEventListener('click', async () => {
          const payload = document.getElementById('input-canary-scan').value;
          const box = document.getElementById('box-canary-scan');
          const badge = document.getElementById('badge-canary-scan');

          try {
            const res = await fetch('/api/v1/security/canary/scan', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ payload: payload })
            });
            const d = await res.json();

            if (d.leaked) {
              badge.textContent = 'Leak Alert!';
              badge.className = 'score-grade grade-block';
              box.innerHTML = `
                <div style="color:var(--red); font-weight:600; margin-bottom:6px;">🚨 CATASTROPHIC CANARY EXFILTRATION DETECTED</div>
                <div><strong>Attribution Tag:</strong> <code>${d.alerts[0].attribution_tag}</code></div>
                <div><strong>Detail:</strong> ${d.alerts[0].message}</div>
              `;
            } else {
              badge.textContent = 'Clean';
              badge.className = 'score-grade grade-allow';
              box.innerHTML = `<span style="color:var(--green)">✓ Payload clean. No honeytoken exfiltration observed.</span>`;
            }
            this.toast('Canary scan complete');
          } catch (err) {
            box.textContent = 'Error: ' + err;
          }
        });
      }

      bindDest() {
        document.getElementById('btn-eval-dest').addEventListener('click', async () => {
          const url = document.getElementById('input-dest').value;
          const box = document.getElementById('box-dest');
          const badge = document.getElementById('badge-dest');

          try {
            const res = await fetch('/api/v1/security/destinations/evaluate', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ destination_url: url })
            });
            const d = await res.json();

            badge.textContent = d.is_trusted ? 'Trusted' : 'Untrusted';
            badge.className = d.is_trusted ? 'score-grade grade-allow' : 'score-grade grade-block';

            box.innerHTML = `
              <div><strong>Target URL:</strong> <code>${d.destination}</code></div>
              <div><strong>Resolved Hostname:</strong> <code>${d.hostname}</code></div>
              <div><strong>Category:</strong> <span class="pill-token">${d.category}</span></div>
              <div><strong>Policy Reason:</strong> ${d.policy_reason}</div>
            `;
            this.toast('Destination policy evaluated');
          } catch (err) {
            box.textContent = 'Error: ' + err;
          }
        });
      }
    }

    function setTestPwd(v) { document.getElementById('input-pwd').value = v; }
    function setVerhoeffVal(v) { document.getElementById('input-verhoeff').value = v; }
    function setDestVal(v) { document.getElementById('input-dest').value = v; }

    window.addEventListener('DOMContentLoaded', () => {
      window.shadeHUD = new ShadeHUD();
    });
  </script>
</body>
</html>"""
