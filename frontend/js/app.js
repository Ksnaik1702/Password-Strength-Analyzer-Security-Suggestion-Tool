/**
 * Password Strength Analyzer & Security Tool - Interactive Client Controller
 * 
 * SECURITY MANDATE:
 * - Does NOT save passwords in localStorage, sessionStorage, cookies, or console.
 * - Show/hide toggle securely adjusts DOM input type only.
 */

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initAnalyzer();
  initGenerator();
  initPolicyChecker();
  initHashingLab();
});

/* ==========================================================================
   1. NAVIGATION & TABS
   ========================================================================== */
function initTabs() {
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabPanels = document.querySelectorAll(".tab-panel");

  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      tabButtons.forEach(b => {
        b.classList.remove("active");
        b.setAttribute("aria-selected", "false");
      });
      tabPanels.forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");

      const targetId = btn.getAttribute("data-tab");
      const targetPanel = document.getElementById(targetId);
      if (targetPanel) {
        targetPanel.classList.add("active");
      }

      // If switching to dashboard tab, refresh stats
      if (targetId === "tab-dashboard") {
        loadDashboardStats();
      }
    });
  });

  const btnRefresh = document.getElementById("btn-refresh-dashboard");
  if (btnRefresh) {
    btnRefresh.addEventListener("click", () => loadDashboardStats());
  }
}

/* ==========================================================================
   2. LIVE PASSWORD ANALYZER
   ========================================================================== */
function initAnalyzer() {
  const passwordInput = document.getElementById("password-input");
  const toggleBtn = document.getElementById("toggle-password-btn");
  const ctxName = document.getElementById("ctx-name");
  const ctxYear = document.getElementById("ctx-year");
  const ctxOrg = document.getElementById("ctx-org");

  // Show / Hide Password toggle
  toggleBtn.addEventListener("click", () => {
    const isPassword = passwordInput.getAttribute("type") === "password";
    passwordInput.setAttribute("type", isPassword ? "text" : "password");
    toggleBtn.textContent = isPassword ? "🙈" : "👁️";
    toggleBtn.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");
  });

  // Debounce keystroke analysis (200ms)
  let debounceTimeout = null;
  const triggerAnalysis = () => {
    clearTimeout(debounceTimeout);
    debounceTimeout = setTimeout(() => {
      performAnalysis(passwordInput.value);
    }, 200);
  };

  passwordInput.addEventListener("input", triggerAnalysis);
  ctxName.addEventListener("input", triggerAnalysis);
  ctxYear.addEventListener("input", triggerAnalysis);
  ctxOrg.addEventListener("input", triggerAnalysis);

  // Demo Chips
  const demoChips = document.querySelectorAll(".demo-chip");
  demoChips.forEach(chip => {
    chip.addEventListener("click", () => {
      const demoPw = chip.getAttribute("data-pw");
      passwordInput.value = demoPw;
      performAnalysis(demoPw);
    });
  });
}

async function performAnalysis(password) {
  const meterFill = document.getElementById("meter-fill");
  const scoreBadge = document.getElementById("score-badge");
  const classBadge = document.getElementById("classification-badge");
  const metricLength = document.getElementById("metric-length");
  const metricLengthBand = document.getElementById("metric-length-band");
  const metricPool = document.getElementById("metric-pool");
  const metricPoolSub = document.getElementById("metric-pool-sub");
  const metricEntropy = document.getElementById("metric-entropy");
  const metricEntropyRating = document.getElementById("metric-entropy-rating");
  const metricCrackTime = document.getElementById("metric-crack-time");
  const findingsList = document.getElementById("findings-list");
  const suggestionsList = document.getElementById("suggestions-list");
  const weaknessCountBadge = document.getElementById("weakness-count-badge");
  const breakdownTbody = document.getElementById("breakdown-tbody");

  if (!password || password.length === 0) {
    meterFill.style.width = "0%";
    meterFill.className = "progress-fill fill-empty";
    scoreBadge.textContent = "0 / 100";
    scoreBadge.className = "score-badge badge-empty";
    classBadge.textContent = "WAITING FOR INPUT";
    classBadge.className = "class-badge class-empty";

    metricLength.textContent = "0";
    metricLengthBand.textContent = "Empty";
    metricPool.textContent = "0";
    metricPoolSub.textContent = "0 Categories";
    metricEntropy.textContent = "0 bits";
    metricEntropyRating.textContent = "None";
    metricCrackTime.textContent = "< 1 ms";

    findingsList.innerHTML = '<div class="empty-state">Enter a password to inspect patterns, sequences, and dictionary matches.</div>';
    suggestionsList.innerHTML = '<li class="suggestion-item">Suggestions will populate in real time based on detected vulnerabilities.</li>';
    weaknessCountBadge.textContent = "0 Issues Found";
    weaknessCountBadge.className = "badge badge-neutral";
    return;
  }

  const payload = {
    password: password,
    first_name: document.getElementById("ctx-name")?.value || null,
    birth_year: document.getElementById("ctx-year")?.value || null,
    organization: document.getElementById("ctx-org")?.value || null
  };

  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!res.ok) throw new Error("Analysis failed");
    const data = await res.json();

    // 1. Update Score & Progress Fill
    const score = data.score;
    meterFill.style.width = `${Math.max(5, score)}%`;
    scoreBadge.textContent = `${score} / 100`;

    // Classes & Colors
    let fillClass = "fill-empty";
    let badgeClass = "class-empty";
    switch (data.classification) {
      case "VERY WEAK": fillClass = "fill-very-weak"; badgeClass = "class-very-weak"; break;
      case "WEAK": fillClass = "fill-weak"; badgeClass = "class-weak"; break;
      case "MODERATE": fillClass = "fill-moderate"; badgeClass = "class-moderate"; break;
      case "STRONG": fillClass = "fill-strong"; badgeClass = "class-strong"; break;
      case "VERY STRONG": fillClass = "fill-very-strong"; badgeClass = "class-very-strong"; break;
    }
    meterFill.className = `progress-fill ${fillClass}`;
    classBadge.textContent = data.classification;
    classBadge.className = `class-badge ${badgeClass}`;

    // 2. Metrics
    const m = data.metrics;
    metricLength.textContent = m.length;
    metricLengthBand.textContent = m.length_band;
    metricPool.textContent = m.character_pool_size;
    metricPoolSub.textContent = `${m.character_type_count} of 4 Categories`;
    metricEntropy.textContent = `${m.entropy_bits} bits`;
    metricEntropyRating.textContent = `${m.entropy_rating} Rating`;
    metricCrackTime.textContent = m.crack_time_educational;

    // 3. Findings
    const negCount = m.weakness_count || 0;
    weaknessCountBadge.textContent = `${negCount} ${negCount === 1 ? 'Issue' : 'Issues'} Found`;
    weaknessCountBadge.className = negCount > 0 ? "badge badge-nist" : "badge badge-privacy";

    if (data.findings && data.findings.length > 0) {
      findingsList.innerHTML = data.findings.map(f => {
        const isPos = f.status === "positive";
        const icon = isPos ? "✅" : (f.severity === "critical" ? "🚨" : "⚠️");
        return `
          <div class="finding-card ${isPos ? 'finding-positive' : 'finding-negative'}">
            <span class="finding-icon">${icon}</span>
            <div class="finding-content">
              <strong>${f.title}</strong>
              <span>${f.description}</span>
            </div>
          </div>
        `;
      }).join("");
    } else {
      findingsList.innerHTML = '<div class="empty-state">No specific pattern weaknesses detected.</div>';
    }

    // 4. Suggestions
    if (data.suggestions && data.suggestions.length > 0) {
      suggestionsList.innerHTML = data.suggestions.map(s => `
        <li class="suggestion-item">${s}</li>
      `).join("");
    }

    // 5. Score Breakdown Table
    const bd = m.score_breakdown || {};
    breakdownTbody.innerHTML = `
      <tr><td>Length Contribution</td><td>+${bd.length_points || 0} pts</td></tr>
      <tr><td>Character Diversity</td><td>+${bd.diversity_points || 0} pts</td></tr>
      <tr><td>Unique Character Ratio</td><td>+${bd.uniqueness_points || 0} pts</td></tr>
      <tr><td>Pattern Resistance Bonus</td><td>+${bd.pattern_resistance_bonus || 0} pts</td></tr>
      <tr><td>Non-Common Password Bonus</td><td>+${bd.non_common_bonus || 0} pts</td></tr>
      <tr><td>Unpredictability Bonus</td><td>+${bd.unpredictability_bonus || 0} pts</td></tr>
      <tr style="color: #fca5a5;"><td>Penalties Deducted</td><td>-${bd.total_penalties || 0} pts</td></tr>
      <tr style="font-weight:700; border-top: 1px solid rgba(255,255,255,0.2);"><td>Final Score (Capped 0-100)</td><td>${score} pts</td></tr>
    `;

  } catch (err) {
    console.error("Analysis request error:", err);
  }
}

/* ==========================================================================
   3. SECURE PASSWORD GENERATOR
   ========================================================================== */
function initGenerator() {
  const radioModes = document.querySelectorAll("input[name='gen-mode']");
  const complexOptions = document.getElementById("complex-options");
  const passphraseOptions = document.getElementById("passphrase-options");
  const lengthSlider = document.getElementById("gen-length-slider");
  const lengthVal = document.getElementById("gen-length-val");
  const wordsSlider = document.getElementById("gen-words-slider");
  const wordsVal = document.getElementById("gen-words-val");
  const btnGenerate = document.getElementById("btn-generate");
  const genOutput = document.getElementById("gen-output");
  const btnCopy = document.getElementById("btn-copy");
  const btnTestGen = document.getElementById("btn-test-generated");
  const copyAlert = document.getElementById("copy-confirmation");

  // Mode radio toggle
  radioModes.forEach(r => {
    r.addEventListener("change", () => {
      if (r.value === "passphrase") {
        complexOptions.classList.add("hidden");
        passphraseOptions.classList.remove("hidden");
      } else {
        complexOptions.classList.remove("hidden");
        passphraseOptions.classList.add("hidden");
      }
    });
  });

  // Slider feedback
  lengthSlider.addEventListener("input", (e) => lengthVal.textContent = e.target.value);
  wordsSlider.addEventListener("input", (e) => wordsVal.textContent = e.target.value);

  // Generate action
  btnGenerate.addEventListener("click", async () => {
    const isPassphrase = document.querySelector("input[name='gen-mode']:checked").value === "passphrase";
    const payload = {
      mode: isPassphrase ? "passphrase" : "complex",
      length: parseInt(lengthSlider.value, 10),
      words_count: parseInt(wordsSlider.value, 10),
      separator: document.getElementById("gen-sep").value || "-",
      include_upper: document.getElementById("gen-opt-upper").checked,
      include_lower: document.getElementById("gen-opt-lower").checked,
      include_digits: document.getElementById("gen-opt-digits").checked,
      include_symbols: document.getElementById("gen-opt-symbols").checked
    };

    try {
      const res = await fetch("/api/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        const data = await res.json();
        genOutput.value = data.generated_password;
      }
    } catch (err) {
      console.error("Generator error:", err);
    }
  });

  // Copy button
  btnCopy.addEventListener("click", () => {
    if (!genOutput.value) return;
    navigator.clipboard.writeText(genOutput.value).then(() => {
      copyAlert.classList.remove("hidden");
      setTimeout(() => copyAlert.classList.add("hidden"), 2500);
    });
  });

  // Test Generated button
  btnTestGen.addEventListener("click", () => {
    if (!genOutput.value) return;
    // Switch to analyzer tab
    document.querySelector("[data-tab='tab-analyzer']").click();
    const pwInput = document.getElementById("password-input");
    pwInput.value = genOutput.value;
    performAnalysis(genOutput.value);
  });
}

/* ==========================================================================
   4. POLICY VALIDATOR
   ========================================================================== */
function initPolicyChecker() {
  const btnCheck = document.getElementById("btn-check-policy");
  const policyInput = document.getElementById("policy-password-input");
  const policyMinLen = document.getElementById("policy-min-len");
  const policyMaxLen = document.getElementById("policy-max-len");
  const policyDisallowCommon = document.getElementById("policy-disallow-common");
  const resultBox = document.getElementById("policy-result-box");
  const statusBadge = document.getElementById("policy-status-badge");
  const rulesList = document.getElementById("policy-rules-list");
  const noteBox = document.getElementById("policy-educational-note");

  btnCheck.addEventListener("click", async () => {
    const pw = policyInput.value;
    if (!pw) return;

    const payload = {
      password: pw,
      min_length: parseInt(policyMinLen.value, 10) || 12,
      max_length: parseInt(policyMaxLen.value, 10) || 128,
      disallow_common: policyDisallowCommon.checked
    };

    try {
      const res = await fetch("/api/policy/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      if (res.ok) {
        const data = await res.json();
        resultBox.classList.remove("hidden");

        statusBadge.textContent = data.status;
        statusBadge.className = data.policy_passed ? "badge badge-privacy" : "badge badge-defensive text-danger";

        rulesList.innerHTML = data.checks.map(c => `
          <li class="${c.passed ? 'policy-pass-item' : 'policy-fail-item'}">
            <span>${c.passed ? '✅' : '❌'}</span>
            <div>
              <strong>${c.rule}</strong>
              <div style="font-size:0.75rem; opacity:0.85;">${c.detail}</div>
            </div>
          </li>
        `).join("");

        noteBox.textContent = data.educational_note;
      }
    } catch (err) {
      console.error("Policy check error:", err);
    }
  });
}

/* ==========================================================================
   5. HASHING LAB
   ========================================================================== */
function initHashingLab() {
  const btnRun = document.getElementById("btn-run-hashing");
  const pwInput = document.getElementById("hash-demo-password");
  const outputDetails = document.getElementById("hash-output-details");
  const valSalt = document.getElementById("hash-val-salt");
  const valDerived = document.getElementById("hash-val-derived");
  const valStored = document.getElementById("hash-val-stored");
  const valInsecure = document.getElementById("hash-val-insecure");

  const btnVerify = document.getElementById("btn-test-verify");
  const verifyInput = document.getElementById("verify-test-input");
  const verifyAlert = document.getElementById("verify-result-alert");

  let currentStoredHash = "";

  btnRun.addEventListener("click", async () => {
    const pw = pwInput.value || "DemoSyntheticPass123!";
    try {
      const res = await fetch("/api/hashing/demonstrate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: pw })
      });

      if (res.ok) {
        const data = await res.json();
        outputDetails.classList.remove("hidden");
        valSalt.textContent = data.salt_hex;
        valDerived.textContent = data.hash_hex;
        valStored.textContent = data.stored_hash_format;
        valInsecure.textContent = data.insecure_fast_sha256;
        currentStoredHash = data.stored_hash_format;
      }
    } catch (err) {
      console.error("Hashing demo error:", err);
    }
  });

  btnVerify.addEventListener("click", async () => {
    if (!currentStoredHash) {
      alert("Please compute a salt and hash first above.");
      return;
    }
    const testPw = verifyInput.value;

    try {
      const res = await fetch("/api/hashing/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          password: testPw,
          stored_hash_format: currentStoredHash
        })
      });

      if (res.ok) {
        const data = await res.json();
        verifyAlert.classList.remove("hidden");
        if (data.is_valid) {
          verifyAlert.textContent = "✅ SUCCESS: Password matches hash! Constant-time comparison verified.";
          verifyAlert.className = "verify-alert verify-match";
        } else {
          verifyAlert.textContent = "❌ MISMATCH: Password incorrect! Hash verification failed.";
          verifyAlert.className = "verify-alert verify-mismatch";
        }
      }
    } catch (err) {
      console.error("Verify error:", err);
    }
  });
}
