const API_ENDPOINT = "https://sentinelguard-worker.surefireprotect.workers.dev/api/v1/inspect";

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only inspect top-level frame navigations (not iframes/ads)
    if (details.frameId !== 0) return;

    const url = details.url;

    // Skip browser internal pages
    if (
        !url.startsWith("http://") &&
        !url.startsWith("https://")
    ) {
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
            const blockPage = chrome.runtime.getURL(
                `blocked.html?threat=${encodeURIComponent(url)}&score=${encodeURIComponent(data.risk_score || 100)}`
            );
            chrome.tabs.update(details.tabId, { url: blockPage });
        }
    } catch (err) {
        console.error("SentinelGuard Backend inspection error:", err);
    }
});