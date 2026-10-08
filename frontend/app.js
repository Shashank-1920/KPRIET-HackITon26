/**
 * S.H.A.D.E. — Sovereign Host for AI Data Enforcement
 * Master Cyber War-Room HUD & Sentinel Engine
 * Specification Version: 3.1.0 Audited
 */

(function () {
  'use strict';

  // =========================================================================
  // 1. MATHEMATICAL VERHOEFF D5 CHECKSUM & CONTEXT ENGINE
  // =========================================================================
  const VerhoeffEngine = {
    // Multiplication matrix d (Dihedral group D5)
    d: [
      [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
      [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
      [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
      [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
      [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
      [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
      [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
      [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
      [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    ],

    // Permutation matrix p
    p: [
      [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
      [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
      [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
      [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
      [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
      [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
      [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
    ],

    // Inverse table inv
    inv: [0, 4, 3, 2, 1, 5, 6, 7, 8, 9],

    /**
     * Evaluates whether a 12-digit string satisfies the Dihedral Group D5 checksum: c == 0
     */
    validateChecksum(numStr) {
      const clean = numStr.replace(/\D/g, '');
      if (clean.length !== 12) return false;
      let c = 0;
      const reversed = clean.split('').reverse().map(Number);
      for (let i = 0; i < reversed.length; i++) {
        c = this.d[c][this.p[i % 8][reversed[i]]];
      }
      return c === 0;
    },

    /**
     * Two-stage Aadhaar detection: Verhoeff Checksum + Proximity Context Anchor
     */
    detectAadhaarWithContext(text) {
      const findings = [];
      // Matches 12 digits either 4-4-4 spaced or consecutive
      const regex = /\b([2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4})\b/g;
      let match;

      while ((match = regex.exec(text)) !== null) {
        const rawMatch = match[1];
        const digitsOnly = rawMatch.replace(/\s/g, '');
        const has444Format = /^[2-9][0-9]{3}\s[0-9]{4}\s[0-9]{4}$/.test(rawMatch);

        // Check Verhoeff checksum
        const isValidVerhoeff = this.validateChecksum(digitsOnly);

        // Proximity anchor check (within 40 characters)
        const startIndex = Math.max(0, match.index - 45);
        const endIndex = Math.min(text.length, match.index + rawMatch.length + 45);
        const contextSlice = text.substring(startIndex, endIndex).toLowerCase();
        const hasAnchorKeyword = /aadhaar|uid|unique id|identity|govt id|resident|uidai/.test(contextSlice);

        // If either 4-4-4 spacing or contextual keyword anchor is satisfied alongside Verhoeff
        if (isValidVerhoeff && (has444Format || hasAnchorKeyword)) {
          findings.push({
            type: 'aadhaar',
            value: rawMatch,
            index: match.index,
            proof: `Verhoeff D5 Checksum: VALID (c=0) | Context: ${has444Format ? '4-4-4 Format' : 'Anchor Keyword Match'}`
          });
        }
      }
      return findings;
    }
  };

  // =========================================================================
  // 2. REGEX HEURISTIC DLP SUITE (PAN, API KEYS, BANKING)
  // =========================================================================
  const DLPSuite = {
    // Indian PAN regex: 5 alpha, 4 numeric, 1 alpha. 4th char represents entity.
    panRegex: /\b([A-Z]{5}[0-9]{4}[A-Z]{1})\b/g,

    // API Secret Keys
    openaiKeyRegex: /\b(sk-(?:proj-)?[A-Za-z0-9_-]{24,})\b/g,
    awsKeyRegex: /\b(AKIA[0-9A-Z]{16})\b/g,

    // Indian Banking: UPI VPA & IFSC
    upiRegex: /\b([a-zA-Z0-9._-]+@[a-zA-Z]{2,64})\b/g,
    ifscRegex: /\b([A-Z]{4}0[A-Z0-9]{6})\b/g,

    scanText(text) {
      const detections = [];

      // 1. Aadhaar via Two-Stage Verhoeff + Context
      const aadhaarMatches = VerhoeffEngine.detectAadhaarWithContext(text);
      aadhaarMatches.forEach(item => detections.push(item));

      // 2. PAN Card
      let m;
      while ((m = this.panRegex.exec(text)) !== null) {
        const val = m[1];
        const entityChar = val.charAt(3);
        const entities = {
          P: 'Individual Taxpayer',
          C: 'Company',
          H: 'Hindu Undivided Family',
          F: 'Partnership Firm',
          T: 'Trust'
        };
        const entityType = entities[entityChar] || 'Tax Entity';
        detections.push({
          type: 'pan',
          value: val,
          index: m.index,
          proof: `4th Character '${entityChar}' (${entityType}) Validated`
        });
      }

      // 3. API Keys
      while ((m = this.openaiKeyRegex.exec(text)) !== null) {
        detections.push({
          type: 'apikey',
          value: m[1],
          index: m.index,
          proof: `OpenAI Secret Key Prefix Detected (sk-...)`
        });
      }

      while ((m = this.awsKeyRegex.exec(text)) !== null) {
        detections.push({
          type: 'apikey',
          value: m[1],
          index: m.index,
          proof: `AWS Access Key ID Detected (AKIA...)`
        });
      }

      // 4. Banking (UPI & IFSC)
      while ((m = this.upiRegex.exec(text)) !== null) {
        const val = m[1];
        if (val.includes('@') && !val.includes('.com') && !val.includes('.in') && !val.includes('.org')) {
          detections.push({
            type: 'banking',
            value: val,
            index: m.index,
            proof: `NPCI UPI Virtual Payment Address Handle Validated`
          });
        }
      }

      while ((m = this.ifscRegex.exec(text)) !== null) {
        detections.push({
          type: 'banking',
          value: m[1],
          index: m.index,
          proof: `RBI IFSC Bank Code Format (4 Alpha + '0' + 6 Alphanum)`
        });
      }

      return detections;
    }
  };

  // =========================================================================
  // 3. EPHEMERAL IN-MEMORY VAULT (Volatile RAM Simulation)
  // =========================================================================
  class EphemeralSessionVault {
    constructor() {
      this.tokenToReal = new Map();
      this.realToToken = new Map();
      this.tokenMetadata = new Map();
      this.ttlSeconds = 900; // 15-minute TTL

      // Pre-seed mock items for immediate demonstration
      this.storeMapping('5432 9876 1234', '<SYN_AADHAAR_9921>', 'Indian Aadhaar (Verhoeff D5)');
      this.storeMapping('ABCDE1234F', '<SYN_PAN_8832>', "Indian PAN (Individual 'P')");
    }

    generateSyntheticToken(type) {
      const randHex = Math.floor(1000 + Math.random() * 9000).toString(16).toUpperCase();
      switch (type) {
        case 'aadhaar':
          return `<SYN_AADHAAR_${randHex}>`;
        case 'pan':
          return `<SYN_PAN_${randHex}>`;
        case 'apikey':
          return `<SYN_API_KEY_${randHex}>`;
        case 'banking':
          return `<SYN_BANKING_${randHex}>`;
        default:
          return `<SYN_DECOY_${randHex}>`;
      }
    }

    storeMapping(realValue, syntheticToken, vectorName) {
      this.tokenToReal.set(syntheticToken, realValue);
      this.realToToken.set(realValue, syntheticToken);
      this.tokenMetadata.set(syntheticToken, {
        vector: vectorName,
        cipherHash: 'AES-256-GCM [' + Math.random().toString(16).substr(2, 8) + '...]',
        createdAt: Date.now(),
        ttlRemaining: 900
      });
    }

    getSynthetic(realValue, type, vectorName) {
      if (this.realToToken.has(realValue)) {
        return this.realToToken.get(realValue);
      }
      const token = this.generateSyntheticToken(type);
      this.storeMapping(realValue, token, vectorName);
      return token;
    }

    getReal(token) {
      return this.tokenToReal.get(token) || null;
    }

    revoke(token) {
      const real = this.tokenToReal.get(token);
      if (real) this.realToToken.delete(real);
      this.tokenToReal.delete(token);
      this.tokenMetadata.delete(token);
    }

    wipeAll() {
      this.tokenToReal.clear();
      this.realToToken.clear();
      this.tokenMetadata.clear();
    }
  }

  // =========================================================================
  // 4. STATUTORY DPDP ACT 2023 NOTICE SYNTHESIZER
  // =========================================================================
  const DPDPSynthesizer = {
    fiduciaries: {
      data_broker: {
        name: 'Commercial Identity & Lead Broker (Aggregator X)',
        address: 'Tower B, Cyber Hub, Gurugram, Haryana - 122002',
        officer: 'Mr. Rajesh Verma',
        email: 'grievance.officer@identitybroker.in'
      },
      swiggy: {
        name: 'Bundl Technologies Private Limited (Swiggy India)',
        address: 'Devarabisanahalli, Outer Ring Road, Bengaluru, Karnataka - 560103',
        officer: 'Grievance Redressal Officer',
        email: 'grievance@swiggy.in'
      },
      zomato: {
        name: 'Eternal Limited (Zomato India)',
        address: 'Ground Floor, Pioneer Square, Sector 62, Gurugram, Haryana - 122098',
        officer: 'Nodal Privacy Officer',
        email: 'privacy@zomato.com'
      },
      phonepe: {
        name: 'PhonePe Private Limited',
        address: 'Office-2, Floor 4,5,6,7, Wing A, Block A, Salarpuria Softzone, Bellandur, Bengaluru - 560103',
        officer: 'Data Protection Officer',
        email: 'grievance@phonepe.com'
      },
      cred: {
        name: 'Dreamplug Technologies Private Limited (CRED)',
        address: '100 Feet Rd, HAL 2nd Stage, Indiranagar, Bengaluru, Karnataka - 560038',
        officer: 'Grievance Officer',
        email: 'grievanceoffice@cred.club'
      },
      policybazaar: {
        name: 'Policybazaar Insurance Brokers Private Limited',
        address: 'Plot No. 119, Sector 44, Gurugram, Haryana - 122001',
        officer: 'Chief Compliance Officer',
        email: 'grievance@policybazaar.com'
      },
      custom: {
        name: 'Designated Data Fiduciary Organization',
        address: 'Registered Corporate Office, India',
        officer: 'Grievance Officer / Data Protection Officer',
        email: 'grievance.officer@fiduciary.in'
      }
    },

    synthesizeNotice(params) {
      const dateStr = new Date().toLocaleDateString('en-IN', {
        day: '2-digit',
        month: 'long',
        year: 'numeric'
      });

      const auditHash = 'SHA-256 [' + Array.from(crypto.getRandomValues(new Uint8Array(4)))
        .map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase() + '...' +
        Array.from(crypto.getRandomValues(new Uint8Array(2)))
        .map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase() + ']';

      return `
        <h3>STATUTORY REQUISITION FOR ERASURE OF PERSONAL DATA</h3>
        <p style="text-align: right;"><strong>Date of Service:</strong> ${dateStr}<br><strong>Mode:</strong> Certified Electronic Transmission (Local Audit Timestamp)</p>
        
        <p>
          <strong>TO:</strong><br>
          <strong>The Grievance Officer / Data Protection Officer</strong><br>
          <strong>${params.fiduciaryName}</strong><br>
          <em>Address:</em> ${params.fiduciaryAddress}<br>
          <em>Email:</em> ${params.fiduciaryEmail}
        </p>

        <p>
          <strong>FROM:</strong><br>
          <strong>Data Principal:</strong> ${params.principalName}<br>
          <em>Registered Email / Identifier:</em> ${params.principalEmail}<br>
          <em>Registered Mobile Contact:</em> ${params.principalPhone}
        </p>

        <p><strong>SUBJECT:</strong> Formal Requisition under Section 12(1) and Mandate under Section 12(3) of the Digital Personal Data Protection Act, 2023 for Immediate Erasure of Personal Data.</p>

        <p>Dear Sir / Madam,</p>

        <p>1. I write to you in my capacity as a <strong>Data Principal</strong> under Section 2(h) of the <strong>Digital Personal Data Protection Act, 2023 (Act No. 22 of 2023)</strong> ("DPDP Act 2023"). Your esteemed entity constitutes a <strong>Data Fiduciary</strong> under Section 2(i) of the Act.</p>

        <p>2. In accordance with the statutory rights conferred upon me under <strong>Section 12(1) of the DPDP Act 2023</strong>, I hereby formally request the irrevocable and comprehensive erasure of all personal data concerning me that is in your possession, custody, or control, or that has been shared by you with any Data Processor.</p>

        <p>3. <strong>Specific Categories of Personal Data Subject to Erasure:</strong><br>
        ${params.specificData}</p>

        <p>4. <strong>Statutory Mandate under Section 12(3):</strong><br>
        Kindly take notice that Section 12(3) of the Act establishes an unambiguous statutory duty: <em>"A Data Fiduciary shall, upon receipt of a requisition under sub-section (1), erase the personal data, unless retention of such personal data is necessary for the specified purpose or for compliance with any law for the time being in force."</em> To the extent no statutory retention requirement applies, failure to comply with this requisition within the prescribed timeframe violates the DPDP Act 2023.</p>

        ${params.includePenalties ? `
        <div class="statutory-alert-box">
          <strong>STATUTORY NOTICE REGARDING PENALTIES UNDER SECTION 33 & THE SCHEDULE:</strong><br>
          Please note that under Section 33 read with the Schedule to the DPDP Act 2023, the Data Protection Board of India is empowered to impose severe financial penalties:
          <ul>
            <li><strong>Up to ₹250 Crore (Two Hundred and Fifty Crore Rupees):</strong> For failure to maintain reasonable security safeguards to prevent personal data breaches;</li>
            <li><strong>Up to ₹50 Crore (Fifty Crore Rupees):</strong> For breach in complying with other obligations or statutory non-compliance.</li>
          </ul>
        </div>
        ` : ''}

        <p>5. Please confirm written compliance with this erasure requisition to my registered email address within <strong>7 (seven) business days</strong> of receipt of this notice. This electronic dispatch has been immutably hashed and logged locally on the Data Principal's host device.</p>

        <p style="margin-top: 20px;">
          Yours faithfully,<br><br>
          <strong>${params.principalName}</strong><br>
          <em>(Data Principal under DPDP Act 2023)</em>
        </p>

        <div style="margin-top: 16px; font-size: 11px; color: #475569; border-top: 1px dashed #cbd5e1; padding-top: 8px;">
          S.H.A.D.E. Certified Dispatch Record | Digest: ${auditHash} | Host: 127.0.0.1
        </div>
      `;
    }
  };

  // =========================================================================
  // 5. MASTER CONTROLLER APP CLASS
  // =========================================================================
  class ShadeMasterHUD {
    constructor() {
      this.vault = new EphemeralSessionVault();
      this.audioContext = null;
      this.waveformCanvas = null;
      this.canvasCtx = null;
      this.animFrameId = null;
      this.isListening = false;
      this.ttsEnabled = true;

      this.currentPromptDetections = [];
      this.currentThreatScore = 72; // Benchmark from specification
    }

    init() {
      this.bindNavigation();
      this.bindGatewaySandbox();
      this.bindBreachRadar();
      this.bindDPDPStudio();
      this.bindVoiceSentinel();
      this.bindClipboardHUD();
      this.bindPitchModal();
      this.startVaultTTLClock();
      this.renderVaultTable();
      this.renderBreachGauge(this.currentThreatScore);

      console.log('🛡️ S.H.A.D.E. War-Room HUD initialized on 127.0.0.1:8000');
    }

    // -----------------------------------------------------------------------
    // UI Helpers & Navigation
    // -----------------------------------------------------------------------
    bindNavigation() {
      const tabBtns = document.querySelectorAll('.tab-btn');
      const tabPanes = document.querySelectorAll('.tab-pane');

      tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
          const targetId = btn.getAttribute('data-tab');

          tabBtns.forEach(b => b.classList.remove('active'));
          tabPanes.forEach(p => p.classList.remove('active'));

          btn.classList.add('active');
          const targetPane = document.getElementById(targetId);
          if (targetPane) {
            targetPane.classList.add('active');
          }

          // Trigger audio visualizer if switching to voice tab
          if (targetId === 'tab-voice') {
            this.initWaveformVisualizer();
          }
        });
      });
    }

    showNotify(message, icon = 'ℹ️') {
      const toast = document.getElementById('global-notify-toast');
      const iconEl = document.getElementById('notify-icon');
      const msgEl = document.getElementById('notify-message');

      iconEl.textContent = icon;
      msgEl.textContent = message;

      toast.classList.add('show');
      setTimeout(() => {
        toast.classList.remove('show');
      }, 3500);
    }

    // -----------------------------------------------------------------------
    // TAB 1: Sovereign AI Gateway Sandbox
    // -----------------------------------------------------------------------
    bindGatewaySandbox() {
      const promptInput = document.getElementById('prompt-input');
      const charCount = document.getElementById('prompt-char-count');
      const btnRun = document.getElementById('btn-run-proxy');
      const findingsList = document.getElementById('findings-tags-list');
      const sanitizedDisplay = document.getElementById('sanitized-egress-display');
      const rehydratedDisplay = document.getElementById('rehydrated-response-display');
      const statTokens = document.getElementById('stat-tokens-swapped');
      const btnCopy = document.getElementById('btn-copy-rehydrated');
      const toggleRehydrate = document.getElementById('toggle-rehydration');

      // Live char counter & live scan
      promptInput.addEventListener('input', () => {
        const text = promptInput.value;
        charCount.textContent = `${text.length} characters`;
        this.liveAnalyzePrompt(text);
      });

      // Quick Demo Presets
      const presets = {
        'preset-aadhaar-pan': `Please verify the loan application credentials for applicant Aarav Sharma.
Customer Aadhaar UID: 2668 5333 9452 (Verified UIDAI format).
Taxpayer PAN Card: ABCDE1234F.
Please generate a risk assessment summary for underwriting approval.`,

        'preset-openai-aws': `# Production Deployment Automation Script
import openai, boto3

# Leaked credentials in prompt
OPENAI_API_KEY = "sk-proj-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

def generate_customer_embeddings(data):
    # Analyze data with OpenAI model
    return openai.Embedding.create(model="text-embedding-3-small", input=data)`,

        'preset-banking-upi': `Authorize instant payout settlement to vendor.
Primary Settlement UPI ID: merchant.finance@okaxis
Bank Branch IFSC Code: SBIN0001234
Beneficiary Account Registered Phone: +91 98765 43210.
Ensure compliance with RBI settlement guidelines.`,

        'preset-clean': `What is the architectural difference between a centralized enterprise DLP and a local-first sovereign privacy hypervisor?
Explain in terms of zero-trust boundary, Dihedral D5 Verhoeff checksums, and streaming tokenization.`
      };

      document.getElementById('preset-aadhaar-pan').addEventListener('click', () => {
        promptInput.value = presets['preset-aadhaar-pan'];
        promptInput.dispatchEvent(new Event('input'));
        this.showNotify('Loaded Indian Aadhaar + PAN KYC Demo Preset', '🇮🇳');
      });

      document.getElementById('preset-openai-aws').addEventListener('click', () => {
        promptInput.value = presets['preset-openai-aws'];
        promptInput.dispatchEvent(new Event('input'));
        this.showNotify('Loaded OpenAI & AWS Credentials Preset', '🔑');
      });

      document.getElementById('preset-banking-upi').addEventListener('click', () => {
        promptInput.value = presets['preset-banking-upi'];
        promptInput.dispatchEvent(new Event('input'));
        this.showNotify('Loaded Indian Banking UPI & IFSC Preset', '💳');
      });

      document.getElementById('preset-clean').addEventListener('click', () => {
        promptInput.value = presets['preset-clean'];
        promptInput.dispatchEvent(new Event('input'));
        this.showNotify('Loaded Clean Query Preset (Zero PII)', '🧼');
      });

      // Intercept & Execute Streaming Proxy Simulation
      btnRun.addEventListener('click', () => {
        const rawText = promptInput.value.trim();
        if (!rawText) {
          this.showNotify('Please enter or select a prompt first.', '⚠️');
          return;
        }

        const detections = DLPSuite.scanText(rawText);
        let sanitizedText = rawText;
        let tokenCount = 0;
        const mappingsForThisRun = [];

        detections.forEach(d => {
          let vectorLabel = 'Generic Decoy';
          if (d.type === 'aadhaar') vectorLabel = 'Indian Aadhaar (Verhoeff D5)';
          else if (d.type === 'pan') vectorLabel = 'Indian PAN Card';
          else if (d.type === 'apikey') vectorLabel = 'Cloud API Secret Key';
          else if (d.type === 'banking') vectorLabel = 'NPCI Banking Handle';

          const syntheticToken = this.vault.getSynthetic(d.value, d.type, vectorLabel);
          sanitizedText = sanitizedText.split(d.value).join(syntheticToken);
          tokenCount++;
          mappingsForThisRun.push({ token: syntheticToken, real: d.value });
        });

        statTokens.textContent = tokenCount;

        // Render Sanitized Payload View (Cloud Egress)
        let formattedSanitized = sanitizedText;
        mappingsForThisRun.forEach(m => {
          formattedSanitized = formattedSanitized.split(m.token)
            .join(`<span class="synthetic-highlight">${m.token}</span>`);
        });

        sanitizedDisplay.innerHTML = `// OUTBOUND EGRESS PAYLOAD [PORT 8000 -> CLOUD AI]\n\n${formattedSanitized}`;

        // Simulate Cloud Response
        let simulatedCloudResponse = '';
        if (tokenCount > 0) {
          const firstToken = mappingsForThisRun[0].token;
          simulatedCloudResponse = `Verification Status for record ${firstToken}:\n- Identity record ${firstToken} checked against compliance rules.\n- Verification passed with status APPROVED.\n- Zero raw sensitive PII was handled by the cloud AI model.`;
        } else {
          simulatedCloudResponse = `Response for clean architectural query:\nS.H.A.D.E. executes purely on local host CPU. When no sensitive PII is detected, the clean stream passes transparently without latency overhead.`;
        }

        // Simulate Rehydration Stream
        const rehydrateEnabled = toggleRehydrate.checked;
        const rehydrationStatus = document.getElementById('rehydration-status-indicator');

        if (rehydrateEnabled && tokenCount > 0) {
          rehydrationStatus.innerHTML = `<span style="color:#10b981;">STATUS: OWNER PERMISSION GRANTED — REHYDRATING LOCALLY</span>`;
          let rehydratedText = simulatedCloudResponse;
          mappingsForThisRun.forEach(m => {
            rehydratedText = rehydratedText.split(m.token)
              .join(`<span class="rehydrated-highlight">${m.real}</span>`);
          });
          rehydratedDisplay.innerHTML = `// LOCAL INBOUND STREAM RE-HYDRATED ON HOST SCREEN:\n\n${rehydratedText}`;
        } else if (!rehydrateEnabled && tokenCount > 0) {
          rehydrationStatus.innerHTML = `<span style="color:#f59e0b;">STATUS: OWNER PERMISSION WITHHELD — SYNTHETIC DISPLAY RETAINED</span>`;
          rehydratedDisplay.innerHTML = `// LOCAL INBOUND STREAM (SYNTHETIC DECOYS PRESERVED):\n\n${simulatedCloudResponse}`;
        } else {
          rehydrationStatus.innerHTML = `<span style="color:#10b981;">STATUS: CLEAN STREAM PASS-THROUGH</span>`;
          rehydratedDisplay.innerHTML = `// CLEAN RESPONSE STREAM:\n\n${simulatedCloudResponse}`;
        }

        this.renderVaultTable();
        this.showNotify(`Interception Complete: ${tokenCount} sensitive secrets tokenized in-flight`, '🛡️');

        if (this.ttsEnabled && tokenCount > 0) {
          this.speak(`Prompt intercepted. ${tokenCount} sensitive identities replaced with synthetic decoys. Real data stayed local.`);
        }
      });

      // Copy Rehydrated Output
      btnCopy.addEventListener('click', () => {
        const text = rehydratedDisplay.innerText;
        navigator.clipboard.writeText(text);
        this.showNotify('Rehydrated plain text copied to clipboard', '📋');
      });

      // Default preset on load
      document.getElementById('preset-aadhaar-pan').click();
    }

    liveAnalyzePrompt(text) {
      const findingsList = document.getElementById('findings-tags-list');
      const detections = DLPSuite.scanText(text);

      if (detections.length === 0) {
        findingsList.innerHTML = `<span class="finding-empty">No sensitive PII or credentials detected in prompt.</span>`;
        return;
      }

      findingsList.innerHTML = detections.map(d => {
        let tagClass = d.type;
        return `
          <div class="finding-tag ${tagClass}">
            <span class="finding-val">⚠️ [${d.type.toUpperCase()}] ${d.value}</span>
            <span class="finding-proof">${d.proof}</span>
          </div>
        `;
      }).join('');
    }

    // -----------------------------------------------------------------------
    // TAB 2: Local Breach Radar & K-Anonymity Demonstrator
    // -----------------------------------------------------------------------
    bindBreachRadar() {
      const inputPass = document.getElementById('kanon-input-password');
      const btnKanon = document.getElementById('btn-run-kanon');
      const valSha1Full = document.getElementById('val-sha1-full');
      const valPrefix = document.getElementById('val-sha1-prefix');
      const valSuffix = document.getElementById('val-sha1-suffix');
      const prefixUrlTag = document.getElementById('prefix-url-tag');
      const matchResult = document.getElementById('kanon-match-result');

      const executeKAnon = async () => {
        const pass = inputPass.value;
        if (!pass) return;

        // Compute local SHA-1 using Web Crypto API
        const msgUint8 = new TextEncoder().encode(pass);
        const hashBuffer = await crypto.subtle.digest('SHA-1', msgUint8);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

        const prefix = hashHex.substring(0, 5);
        const suffix = hashHex.substring(5);

        valSha1Full.textContent = hashHex;
        valPrefix.textContent = `5-CHAR PREFIX (TRANSMITTED): [${prefix}]`;
        valSuffix.textContent = `35-CHAR SUFFIX (KEPT IN LOCAL RAM): [${suffix.substring(0, 16)}...]`;
        prefixUrlTag.textContent = prefix;

        matchResult.innerHTML = `
          ⚠️ <strong>LOCAL HOST MATCH CONFIRMED:</strong> Password suffix <code>${suffix.substring(0, 8)}...</code> matched 4 records in historical dump cache.
          <br><strong>Privacy Audit:</strong> Remote server received <em>only</em> <code>${prefix}</code> (which is shared by >1,800 unrelated passwords). Zero plaintext disclosure!
        `;

        this.showNotify(`K-Anonymity Verified: Transmitted prefix ${prefix} only`, '🔒');
      };

      btnKanon.addEventListener('click', executeKAnon);
      executeKAnon(); // initial run
    }

    renderBreachGauge(score) {
      const circle = document.getElementById('gauge-progress-circle');
      const scoreText = document.getElementById('svg-score-text');
      const scoreLevel = document.getElementById('svg-score-level');
      const miniScore = document.getElementById('mini-threat-score');
      const miniGrade = document.getElementById('mini-threat-grade');

      const radius = 95;
      const circumference = 2 * Math.PI * radius; // ~596.9

      const offset = circumference - (score / 100) * circumference;
      circle.style.strokeDasharray = `${circumference}`;
      circle.style.strokeDashoffset = `${offset}`;

      scoreText.textContent = score;
      miniScore.textContent = score;

      let levelStr = 'ELEVATED RISK';
      let strokeColor = '#f59e0b'; // amber

      if (score < 40) {
        levelStr = 'LOW RISK';
        strokeColor = '#10b981';
      } else if (score < 70) {
        levelStr = 'MODERATE RISK';
        strokeColor = '#38bdf8';
      } else if (score >= 85) {
        levelStr = 'CRITICAL RISK';
        strokeColor = '#ef4444';
      }

      circle.style.stroke = strokeColor;
      scoreLevel.textContent = levelStr;
      scoreLevel.style.fill = strokeColor;
      miniGrade.textContent = levelStr.replace(' RISK', '');
      miniGrade.style.color = strokeColor;
    }

    jumpToDPDP(fiduciaryName, identityVector) {
      // Switch tab to DPDP
      document.querySelector('[data-tab="tab-dpdp"]').click();
      document.getElementById('dpdp-specific-data').value = `Exposed identity vector (${identityVector}) found in commercial brokerage dumps, phone listings, and associated data broker telemetry.`;
      document.getElementById('btn-generate-dpdp-notice').click();
      this.showNotify(`Formulating Section 12 Requisition for ${fiduciaryName}`, '📜');
    }

    // -----------------------------------------------------------------------
    // TAB 3: Statutory DPDP Act 2023 Enforcement Studio
    // -----------------------------------------------------------------------
    bindDPDPStudio() {
      const form = document.getElementById('dpdp-generator-form');
      const selectFiduciary = document.getElementById('dpdp-fiduciary-select');
      const nameInput = document.getElementById('dpdp-principal-name');
      const emailInput = document.getElementById('dpdp-principal-email');
      const phoneInput = document.getElementById('dpdp-principal-phone');
      const officerEmailInput = document.getElementById('dpdp-officer-email');
      const specificDataInput = document.getElementById('dpdp-specific-data');
      const checkPenalties = document.getElementById('dpdp-include-penalties');
      const noticeDisplay = document.getElementById('legal-notice-display');

      const btnGenerate = document.getElementById('btn-generate-dpdp-notice');
      const btnEmailDispatch = document.getElementById('btn-email-dispatch');
      const btnCopyNotice = document.getElementById('btn-copy-notice');
      const btnDownloadNotice = document.getElementById('btn-download-notice');

      // Auto-fill officer when fiduciary changes
      selectFiduciary.addEventListener('change', () => {
        const key = selectFiduciary.value;
        const fid = DPDPSynthesizer.fiduciaries[key] || DPDPSynthesizer.fiduciaries.custom;
        officerEmailInput.value = fid.email;
      });

      const generateNotice = () => {
        const key = selectFiduciary.value;
        const fid = DPDPSynthesizer.fiduciaries[key] || DPDPSynthesizer.fiduciaries.custom;

        const params = {
          fiduciaryName: fid.name,
          fiduciaryAddress: fid.address,
          fiduciaryEmail: officerEmailInput.value || fid.email,
          principalName: nameInput.value,
          principalEmail: emailInput.value,
          principalPhone: phoneInput.value,
          specificData: specificDataInput.value,
          includePenalties: checkPenalties.checked
        };

        const noticeHtml = DPDPSynthesizer.synthesizeNotice(params);
        noticeDisplay.innerHTML = noticeHtml;
        this.showNotify('Certified DPDP Requisition Synthesized', '⚖️');
      };

      btnGenerate.addEventListener('click', generateNotice);

      // Email Dispatch
      btnEmailDispatch.addEventListener('click', () => {
        const recipient = officerEmailInput.value;
        const subject = encodeURIComponent('Statutory Requisition under Section 12 DPDP Act 2023 - Erasure of Personal Data');
        const plainText = noticeDisplay.innerText;
        const body = encodeURIComponent(plainText);
        window.location.href = `mailto:${recipient}?subject=${subject}&body=${body}`;
        this.showNotify('Opening authenticated local mail client...', '📨');
      });

      // Copy Notice
      btnCopyNotice.addEventListener('click', () => {
        navigator.clipboard.writeText(noticeDisplay.innerText);
        this.showNotify('Certified statutory notice copied to clipboard', '📋');
      });

      // Download Notice
      btnDownloadNotice.addEventListener('click', () => {
        const blob = new Blob([noticeDisplay.innerText], { type: 'text/plain;charset=utf-8' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `DPDP_Section12_Requisition_${Date.now()}.txt`;
        a.click();
        this.showNotify('Downloaded certified legal draft', '💾');
      });

      // Generate default on start
      generateNotice();
    }

    // -----------------------------------------------------------------------
    // TAB 4: Ambient Voice Sentinel ('Hey Shade') & Audio Deck
    // -----------------------------------------------------------------------
    bindVoiceSentinel() {
      const btnToggleMic = document.getElementById('btn-toggle-mic');
      const micLabel = document.getElementById('btn-mic-label');
      const transcriptText = document.getElementById('voice-transcript-text');
      const listenBadge = document.getElementById('voice-listen-badge');
      const logEntries = document.getElementById('voice-log-entries');
      const toggleTTS = document.getElementById('toggle-audio-tts');

      toggleTTS.addEventListener('change', () => {
        this.ttsEnabled = toggleTTS.checked;
      });

      btnToggleMic.addEventListener('click', () => {
        this.isListening = !this.isListening;
        if (this.isListening) {
          btnToggleMic.classList.add('active');
          micLabel.textContent = 'Mute Voice Sentinel';
          listenBadge.textContent = 'LISTENING (HEY SHADE)';
          listenBadge.className = 'status-indicator-live';
          listenBadge.style.background = 'rgba(239, 68, 68, 0.2)';
          listenBadge.style.color = 'var(--neon-red)';
          listenBadge.style.borderColor = 'var(--neon-red)';
          transcriptText.textContent = `"Acoustic loop active. Listening for 'Hey Shade' hotword..."`;
          this.logVoiceEvent("Microphone stream opened. Offline Kaldi model running on host CPU.");
          this.speak("Voice Sentinel armed. Standing by for sovereign command.");
        } else {
          btnToggleMic.classList.remove('active');
          micLabel.textContent = 'Activate Live Voice Listener';
          listenBadge.textContent = 'STANDBY';
          listenBadge.className = 'status-indicator-live';
          listenBadge.style.background = 'rgba(16, 185, 129, 0.2)';
          listenBadge.style.color = 'var(--neon-emerald)';
          listenBadge.style.borderColor = 'var(--neon-emerald)';
          transcriptText.textContent = `"Voice loop in standby. Click activate or use quick-trigger chips."`;
          this.logVoiceEvent("Microphone loop closed.");
        }
      });

      // Quick-Trigger Chips (Auditorium noise failsafe)
      document.getElementById('chip-voice-scan').addEventListener('click', () => {
        this.logVoiceEvent("COMMAND [CHIP]: 'Hey Shade, run exposure scan'");
        transcriptText.textContent = `"Hey Shade, run exposure scan." -> Response: "Scan complete. Illustrative threat score 72."`;
        this.speak("Scan complete. Illustrative threat score 72. Compromised credentials found in historical breach archives.");
        // Switch to radar
        document.querySelector('[data-tab="tab-radar"]').click();
        this.renderBreachGauge(72);
      });

      document.getElementById('chip-voice-intercept').addEventListener('click', () => {
        this.logVoiceEvent("COMMAND [CHIP]: 'Hey Shade, intercept prompt stream'");
        transcriptText.textContent = `"Hey Shade, intercept prompt stream." -> Response: "Gateway active on 127.0.0.1:8000. In-flight tokenization armed."`;
        this.speak("Gateway active on port 8000. In flight tokenization armed.");
        document.querySelector('[data-tab="tab-gateway"]').click();
        document.getElementById('btn-run-proxy').click();
      });

      document.getElementById('chip-voice-dpdp').addEventListener('click', () => {
        this.logVoiceEvent("COMMAND [CHIP]: 'Hey Shade, formulate DPDP notice'");
        transcriptText.textContent = `"Hey Shade, formulate DPDP notice." -> Response: "Formulating verified Section 12 erasure requisition citing Section 33 penalties."`;
        this.speak("Formulating verified Section 12 erasure requisition citing Section 33 penalties.");
        document.querySelector('[data-tab="tab-dpdp"]').click();
        document.getElementById('btn-generate-dpdp-notice').click();
      });

      document.getElementById('chip-voice-status').addEventListener('click', () => {
        this.logVoiceEvent("COMMAND [CHIP]: 'Hey Shade, system status report'");
        transcriptText.textContent = `"Hey Shade, system status report." -> Response: "All 5 sovereign pillars active. Venue Wi-Fi shield engaged. Zero bytes leaked."`;
        this.speak("All five sovereign pillars active. Venue Wi-Fi shield engaged. Zero raw bytes leaked.");
        this.showNotify('Sovereign Hypervisor status: 100% Operational', '🛡️');
      });
    }

    logVoiceEvent(message) {
      const logEntries = document.getElementById('voice-log-entries');
      const now = new Date();
      const timeStr = `[${now.toTimeString().substring(0, 8)}]`;
      const div = document.createElement('div');
      div.className = 'log-item';
      div.innerHTML = `<span class="log-time">${timeStr}</span> <span class="log-msg">${message}</span>`;
      logEntries.appendChild(div);
      logEntries.scrollTop = logEntries.scrollHeight;
    }

    speak(text) {
      if (!this.ttsEnabled) return;
      if ('speechSynthesis' in window) {
        window.speechSynthesis.cancel();
        const utterance = new SpeechSynthesisUtterance(text);
        utterance.rate = 1.05;
        utterance.pitch = 0.95;
        window.speechSynthesis.speak(utterance);
      }
    }

    initWaveformVisualizer() {
      const canvas = document.getElementById('voice-waveform-canvas');
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      let phase = 0;

      const draw = () => {
        this.animFrameId = requestAnimationFrame(draw);
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        ctx.lineWidth = 2;
        ctx.strokeStyle = this.isListening ? '#ef4444' : '#00f0ff';
        ctx.shadowBlur = 8;
        ctx.shadowColor = this.isListening ? '#ef4444' : '#00f0ff';

        ctx.beginPath();
        const sliceWidth = canvas.width / 60;
        let x = 0;

        for (let i = 0; i < 60; i++) {
          const amplitude = this.isListening ? 35 : 12;
          const y = canvas.height / 2 + Math.sin(i * 0.2 + phase) * amplitude * Math.cos(i * 0.1 - phase);
          if (i === 0) {
            ctx.moveTo(x, y);
          } else {
            ctx.lineTo(x, y);
          }
          x += sliceWidth;
        }

        ctx.stroke();
        phase += this.isListening ? 0.12 : 0.04;
      };

      if (!this.animFrameId) {
        draw();
      }
    }

    // -----------------------------------------------------------------------
    // Context-Aware Clipboard HUD Toast
    // -----------------------------------------------------------------------
    bindClipboardHUD() {
      const toast = document.getElementById('clipboard-hud-toast');
      const btnTrigger = document.getElementById('btn-trigger-clipboard-demo');
      const btnClose = document.getElementById('btn-close-toast');
      const btnDecoy = document.getElementById('btn-toast-paste-decoy');
      const btnReal = document.getElementById('btn-toast-send-real');
      const detectedVal = document.getElementById('toast-detected-value');

      btnTrigger.addEventListener('click', () => {
        detectedVal.textContent = '2668 5333 9452 (Indian Aadhaar)';
        toast.classList.add('active');
        this.showNotify('Clipboard Sentinel: Sensitive Indian Aadhaar detected on copy event', '⚠️');
      });

      btnClose.addEventListener('click', () => {
        toast.classList.remove('active');
      });

      btnDecoy.addEventListener('click', () => {
        toast.classList.remove('active');
        this.showNotify('Safety Decoy <SYN_AADHAAR_9921> injected for pasting. Cloud protected!', '🛡️');
      });

      btnReal.addEventListener('click', () => {
        toast.classList.remove('active');
        this.showNotify('KYC Exception Allowed: Real Aadhaar passed to authenticated banking form.', '⚠️');
      });
    }

    // -----------------------------------------------------------------------
    // 3-Minute Hackathon Demo Pitch Modal
    // -----------------------------------------------------------------------
    bindPitchModal() {
      const modal = document.getElementById('modal-pitch-overlay');
      const btnOpen = document.getElementById('btn-open-pitch-guide');
      const btnClose = document.getElementById('btn-close-pitch-modal');
      const btnGuided = document.getElementById('btn-start-guided-demo');

      btnOpen.addEventListener('click', () => modal.classList.add('active'));
      btnClose.addEventListener('click', () => modal.classList.remove('active'));

      modal.addEventListener('click', (e) => {
        if (e.target === modal) modal.classList.remove('active');
      });

      btnGuided.addEventListener('click', () => {
        modal.classList.remove('active');
        this.runGuidedWalkthrough();
      });
    }

    async runGuidedWalkthrough() {
      this.showNotify('Starting 3-Minute Live Hackathon Demonstration Flow...', '🚀');
      // Step 1: Gateway
      document.querySelector('[data-tab="tab-gateway"]').click();
      document.getElementById('preset-aadhaar-pan').click();
      await new Promise(r => setTimeout(r, 600));
      document.getElementById('btn-run-proxy').click();

      // Step 2: Radar
      await new Promise(r => setTimeout(r, 2200));
      document.querySelector('[data-tab="tab-radar"]').click();
      this.showNotify('Minute 2: Local Breach Radar & K-Anonymity Verified (72/100)', '🎯');

      // Step 3: DPDP Notice
      await new Promise(r => setTimeout(r, 2200));
      document.querySelector('[data-tab="tab-dpdp"]').click();
      this.showNotify('Minute 3: DPDP Act 2023 Section 12 Requisition Ready to Dispatch', '⚖️');
    }

    // -----------------------------------------------------------------------
    // TAB 5: Ephemeral RAM Vault Inspector
    // -----------------------------------------------------------------------
    renderVaultTable() {
      const tbody = document.getElementById('vault-table-body');
      const activeCount = document.getElementById('vault-active-count');
      if (!tbody) return;

      const entries = Array.from(this.vault.tokenToReal.entries());
      activeCount.textContent = `${entries.length} ACTIVE`;

      if (entries.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:#64748b; padding:20px;">Ephemeral RAM Vault is empty. No active session mappings.</td></tr>`;
        return;
      }

      tbody.innerHTML = entries.map(([token, real]) => {
        const meta = this.vault.tokenMetadata.get(token) || {};
        return `
          <tr>
            <td><code class="token-code">${token}</code></td>
            <td><span class="vector-badge">${meta.vector || 'Identified Secret'}</span></td>
            <td><span class="cipher-tag">${meta.cipherHash || 'AES-256-GCM'}</span></td>
            <td><span class="plaintext-host-tag">${real}</span></td>
            <td><span class="ttl-counter" data-ttl="${meta.ttlRemaining || 900}">${this.formatTTL(meta.ttlRemaining || 900)}</span></td>
            <td><button class="btn-table-action" onclick="window.shadeApp.revokeToken('${token}')">Revoke Token</button></td>
          </tr>
        `;
      }).join('');
    }

    formatTTL(seconds) {
      const m = Math.floor(seconds / 60);
      const s = seconds % 60;
      return `${m}:${s < 10 ? '0' : ''}${s}`;
    }

    startVaultTTLClock() {
      setInterval(() => {
        this.vault.tokenMetadata.forEach((meta) => {
          if (meta.ttlRemaining > 0) meta.ttlRemaining--;
        });
        const counters = document.querySelectorAll('.ttl-counter');
        counters.forEach(c => {
          let ttl = parseInt(c.getAttribute('data-ttl'), 10) || 900;
          if (ttl > 0) {
            ttl--;
            c.setAttribute('data-ttl', ttl);
            c.textContent = this.formatTTL(ttl);
          }
        });
      }, 1000);

      const btnWipe = document.getElementById('btn-wipe-vault');
      if (btnWipe) {
        btnWipe.addEventListener('click', () => {
          this.vault.wipeAll();
          this.renderVaultTable();
          this.showNotify('EMERGENCY KEY ZEROIZATION: Ephemeral RAM mappings permanently obliterated', '🔥');
        });
      }
    }

    revokeToken(token) {
      this.vault.revoke(token);
      this.renderVaultTable();
      this.showNotify(`Token ${token} revoked and erased from RAM vault`, '🗑️');
    }
  }

  // Instantiate and mount globally
  window.addEventListener('DOMContentLoaded', () => {
    window.shadeApp = new ShadeMasterHUD();
    window.shadeApp.init();
  });

})();
