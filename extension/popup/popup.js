const API_ENDPOINT = "https://sentinelguard-worker.surefireprotect.workers.dev/";

let currentActiveTab = null;
let currentTabRisk = { score: 0, decision: "ALLOW" };

// Playbook response templates
const PLAYBOOKS = {
    credentials: [
        "Navigate directly to the legitimate service and change password immediately.",
        "Force logout all active sessions across all devices in account settings.",
        "Enable Hardware or App-based Two-Factor Authentication (2FA)."
    ],
    financial: [
        "Call the emergency fraud number on the back of your physical card immediately.",
        "Request an instant card lock / freeze on your mobile banking app.",
        "Monitor transactions for unauthorized test charges ($0.01 - $1.00)."
    ],
    download: [
        "Do NOT execute or open the downloaded file.",
        "Locate the file in your Downloads directory and permanently delete (Shift+Delete).",
        "Run a full offline anti-malware scan immediately."
    ]
};

document.addEventListener("DOMContentLoaded", async () => {
    // 1. Setup buttons FIRST so UI doesn't freeze
    setupEventListeners();
    renderPlaybook("credentials");

    // 2. Fetch risk data in the background
    await fetchActiveTabInfo();
});

// 1. Query Active Tab & Backend Risk Assessment
async function fetchActiveTabInfo() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) return;

    currentActiveTab = tab;

    const currentUrlEl = document.getElementById("current-url");
    if (currentUrlEl) currentUrlEl.textContent = tab.url;

    if (tab.url.startsWith("chrome://") || tab.url.startsWith("edge://") || tab.url.startsWith("about:")) {
        document.getElementById("risk-score-display").textContent = "Safe (Internal)";
        updateMeter(0);
        return;
    }

    try {
        const res = await fetch(API_ENDPOINT, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: tab.url })
        });

        if (res.ok) {
            const data = await res.json();
            currentTabRisk = { score: data.risk_score, decision: data.decision };
            document.getElementById("risk-score-display").textContent = `${data.risk_score} / 100`;
            updateMeter(data.risk_score);
        }
    } catch (err) {
        document.getElementById("risk-score-display").textContent = "Offline";
    }
}

function updateMeter(score) {
    const fill = document.getElementById("meter-fill");
    if (!fill) return;

    fill.style.width = `${score}%`;

    if (score >= 75) {
        fill.style.backgroundColor = "#ef4444"; // Red
    } else if (score >= 40) {
        fill.style.backgroundColor = "#f59e0b"; // Amber
    } else {
        fill.style.backgroundColor = "#10b981"; // Green
    }
}

// 2. Event Listeners & Kill Switch Logic
function setupEventListeners() {
    const killSwitchBtn = document.getElementById("kill-switch-btn");
    const triagePanel = document.getElementById("triage-panel");
    const closeTriageBtn = document.getElementById("close-triage-btn");
    const downloadBtn = document.getElementById("download-forensics-btn");
    const closeTabBtn = document.getElementById("close-tab-btn");

    if (killSwitchBtn && triagePanel) {
        // Toggle Triage Panel & Trigger Local Incident Capture
        killSwitchBtn.addEventListener("click", async () => {
            triagePanel.classList.remove("hidden");
            await logIncident("User Triggered Kill Switch");
        });
    }

    if (closeTriageBtn && triagePanel) {
        closeTriageBtn.addEventListener("click", () => {
            triagePanel.classList.add("hidden");
        });
    }

    // Dynamic Radio change for breach type
    document.querySelectorAll('input[name="breach_type"]').forEach((elem) => {
        elem.addEventListener("change", (e) => {
            renderPlaybook(e.target.value);
        });
    });

    if (downloadBtn) downloadBtn.addEventListener("click", exportForensicReport);

    if (closeTabBtn) {
        closeTabBtn.addEventListener("click", () => {
            if (currentActiveTab && currentActiveTab.id) {
                chrome.tabs.remove(currentActiveTab.id);
                window.close(); // Close the popup
            }
        });
    }
}

function renderPlaybook(type) {
    const container = document.getElementById("playbook-steps");
    if (!container) return;

    const steps = PLAYBOOKS[type] || [];

    let html = "<ol>";
    steps.forEach((step) => {
        html += `<li>${step}</li>`;
    });
    html += "</ol>";

    container.innerHTML = html;
}

// 3. Incident Logging & Immutable Evidence Report
async function logIncident(reason) {
    const typeInput = document.querySelector('input[name="breach_type"]:checked');
    const selectedType = typeInput ? typeInput.value : "unknown";

    const incidentEntry = {
        incident_id: "INC-" + Date.now(),
        timestamp: new Date().toISOString(),
        url: currentActiveTab?.url || "unknown",
        title: currentActiveTab?.title || "unknown",
        risk_score: currentTabRisk.score,
        decision: currentTabRisk.decision,
        breach_type: selectedType,
        trigger_reason: reason,
        user_agent: navigator.userAgent
    };

    // Persist locally in extension storage
    const data = await chrome.storage.local.get({ incident_logs: [] });
    data.incident_logs.push(incidentEntry);
    await chrome.storage.local.set({ incident_logs: data.incident_logs });
}

async function exportForensicReport() {
    const data = await chrome.storage.local.get({ incident_logs: [] });
    const latestIncident = data.incident_logs[data.incident_logs.length - 1] || {
        incident_id: "INC-" + Date.now(),
        timestamp: new Date().toISOString(),
        url: currentActiveTab?.url || "unknown",
        risk_score: currentTabRisk.score
    };

    const blob = new Blob([JSON.stringify(latestIncident, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinelguard-evidence-${latestIncident.incident_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
}