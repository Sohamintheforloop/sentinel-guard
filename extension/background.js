const API_ENDPOINT = "http://127.0.0.1:8000/api/v1/inspect";

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only inspect top-level frame navigations (not iframes/ads)
    if (details.frameId !== 0) return;

    const url = details.url;

    // Skip browser internal pages
    if (url.startsWith("chrome://") || url.startsWith("edge://") || url.startsWith("about:")) {
        return;
    }

    try {
        const response = await fetch(API_ENDPOINT, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) return;

        const data = await response.json();

        // If high risk, instruct the content script to block the page
        if (data.decision === "BLOCK") {
            chrome.tabs.sendMessage(details.tabId, {
                action: "BLOCK_PAGE",
                url: data.url,
                riskScore: data.risk_score
            }).catch(() => {
                // Tab might not be ready yet; content script will handle on load
            });
        }
    } catch (err) {
        console.error("SentinelGuard Backend unreachable:", err);
    }
});