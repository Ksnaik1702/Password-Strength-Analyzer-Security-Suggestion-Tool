/**
 * Dashboard & Telemetry Visualizations
 * Renders Chart.js graphics based on anonymous aggregate metrics.
 * GUARANTEE: Never renders or consumes plaintext credentials.
 */

let chartClassificationsInstance = null;
let chartLengthsInstance = null;
let chartWeaknessesInstance = null;

async function loadDashboardStats() {
  try {
    const res = await fetch("/api/dashboard/stats");
    if (!res.ok) return;
    const data = await res.json();

    // 1. Update Counter Cards
    const total = data.total_analyses || 0;
    document.getElementById("dash-total-count").textContent = total.toLocaleString();
    document.getElementById("dash-avg-score").textContent = data.average_score.toFixed(1);

    const classes = data.classifications || {};
    const weakTotal = (classes["VERY WEAK"] || 0) + (classes["WEAK"] || 0);
    const strongTotal = (classes["STRONG"] || 0) + (classes["VERY STRONG"] || 0);

    const weakPct = total > 0 ? Math.round((weakTotal / total) * 100) : 0;
    const strongPct = total > 0 ? Math.round((strongTotal / total) * 100) : 0;

    document.getElementById("dash-weak-pct").textContent = `${weakPct}%`;
    document.getElementById("dash-strong-pct").textContent = `${strongPct}%`;

    // 2. Render Classifications Doughnut Chart
    renderClassificationsChart(classes);

    // 3. Render Length Distribution Chart
    renderLengthsChart(data.length_distribution || {});

    // 4. Render Weaknesses Frequency Chart
    renderWeaknessesChart(data.weakness_frequency || []);

    // 5. Populate Recent Telemetry Table
    renderRecentTable(data.recent_analyses || []);

  } catch (err) {
    console.warn("Could not fetch dashboard telemetry:", err);
  }
}

function renderClassificationsChart(classes) {
  const ctx = document.getElementById("chart-classifications");
  if (!ctx) return;

  const labels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"];
  const values = [
    classes["VERY WEAK"] || 0,
    classes["WEAK"] || 0,
    classes["MODERATE"] || 0,
    classes["STRONG"] || 0,
    classes["VERY STRONG"] || 0
  ];

  if (chartClassificationsInstance) {
    chartClassificationsInstance.destroy();
  }

  chartClassificationsInstance = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: labels,
      datasets: [{
        data: values,
        backgroundColor: [
          "#ef4444", // Very Weak
          "#f97316", // Weak
          "#eab308", // Moderate
          "#0ea5e9", // Strong
          "#10b981"  // Very Strong
        ],
        borderWidth: 1,
        borderColor: "#1e293b"
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: { color: "#94a3b8", font: { size: 11 } }
        }
      }
    }
  });
}

function renderLengthsChart(lengthDist) {
  const ctx = document.getElementById("chart-lengths");
  if (!ctx) return;

  const labels = Object.keys(lengthDist);
  const values = Object.values(lengthDist);

  if (chartLengthsInstance) {
    chartLengthsInstance.destroy();
  }

  chartLengthsInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [{
        label: "Number of Evaluations",
        data: values,
        backgroundColor: "rgba(59, 130, 246, 0.7)",
        borderColor: "#3b82f6",
        borderWidth: 1,
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: { ticks: { color: "#94a3b8" }, grid: { color: "rgba(255,255,255,0.05)" } },
        y: { ticks: { color: "#94a3b8", stepSize: 1 }, grid: { color: "rgba(255,255,255,0.05)" } }
      }
    }
  });
}

function renderWeaknessesChart(weaknesses) {
  const ctx = document.getElementById("chart-weaknesses");
  if (!ctx) return;

  const labels = weaknesses.map(w => w.type.replace(/_/g, " ").toUpperCase());
  const values = weaknesses.map(w => w.count);

  if (chartWeaknessesInstance) {
    chartWeaknessesInstance.destroy();
  }

  chartWeaknessesInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels.length ? labels : ["No Weaknesses"],
      datasets: [{
        label: "Detections",
        data: values.length ? values : [0],
        backgroundColor: "rgba(244, 63, 94, 0.7)",
        borderColor: "#f43f5e",
        borderWidth: 1,
        borderRadius: 4
      }]
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: { ticks: { color: "#94a3b8", stepSize: 1 }, grid: { color: "rgba(255,255,255,0.05)" } },
        y: { ticks: { color: "#94a3b8", font: { size: 10 } }, grid: { display: false } }
      }
    }
  });
}

function renderRecentTable(recent) {
  const tbody = document.getElementById("recent-analyses-tbody");
  if (!tbody) return;

  if (!recent || recent.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No telemetry recorded yet.</td></tr>';
    return;
  }

  tbody.innerHTML = recent.map(r => {
    const shortId = r.analysis_id ? r.analysis_id.slice(0, 8) : "N/A";
    const classColor = getClassColor(r.classification);
    return `
      <tr>
        <td><code>${shortId}</code></td>
        <td><strong>${r.score}</strong></td>
        <td><span style="color:${classColor}; font-weight:700;">${r.classification}</span></td>
        <td>${r.password_length} chars</td>
        <td>${r.weakness_count}</td>
      </tr>
    `;
  }).join("");
}

function getClassColor(classification) {
  switch (classification) {
    case "VERY WEAK": return "#ef4444";
    case "WEAK": return "#f97316";
    case "MODERATE": return "#eab308";
    case "STRONG": return "#0ea5e9";
    case "VERY STRONG": return "#10b981";
    default: return "#94a3b8";
  }
}
