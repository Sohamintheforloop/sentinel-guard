chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "BLOCK_PAGE") {
        renderBlockScreen(message.url, message.riskScore);
    }
});

function renderBlockScreen(url, score) {
    // Avoid duplicate overlays
    if (document.getElementById("sentinel-overlay")) return;

    const overlay = document.createElement("div");
    overlay.id = "sentinel-overlay";
    overlay.innerHTML = `
    <div class="sentinel-card">
      <div class="sentinel-badge">THREAT BLOCKED</div>
      <h1>Dangerous Site Ahead</h1>
      <p>SentinelGuard detected suspicious patterns associated with phishing and credential theft on this page.</p>
      
      <div class="sentinel-stats">
        <div><strong>URL:</strong> ${url}</div>
        <div><strong>Assigned Risk Score:</strong> <span class="score-danger">${score} / 100</span></div>
      </div>

      <div class="sentinel-actions">
        <button id="sentinel-back-btn" class="btn-primary">Take Me to Safety</button>
      </div>
    </div>
  `;

    document.documentElement.appendChild(overlay);

    document.getElementById("sentinel-back-btn").addEventListener("click", () => {
        window.location.href = "https://www.google.com";
    });
}