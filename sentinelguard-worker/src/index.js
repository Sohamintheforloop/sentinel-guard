const SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "banking", "wallet", "signin", "password", "confirm"
];

function evaluateUrlRisk(urlString) {
    let url;
    try {
        url = new URL(urlString);
    } catch {
        return { risk_score: 50, decision: "WARN", details: "Malformed URL" };
    }

    const hostname = url.hostname.toLowerCase();
    const fullUrl = url.href.toLowerCase();

    let score = 0;

    // 1. IP address in hostname (+40 points)
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) score += 40;

    // 2. '@' symbol in URL (+35 points)
    if (fullUrl.includes("@")) score += 35;

    // 3. Excessive subdomains (+12 points per extra subdomain, up to 30)
    const domainParts = hostname.split(".");
    const subdomainCount = Math.max(0, domainParts.length - 2);
    score += Math.min(subdomainCount * 12, 30);

    // 4. Excessive hyphens (+6 each, up to 24)
    const hyphenCount = (hostname.match(/-/g) || []).length;
    score += Math.min(hyphenCount * 6, 24);

    // 5. Suspicious keywords (+15 each, up to 45)
    let keywordHits = 0;
    for (const kw of SUSPICIOUS_KEYWORDS) {
        if (fullUrl.includes(kw)) keywordHits++;
    }
    score += Math.min(keywordHits * 15, 45);

    // 6. Suspicious TLDs (+20 points)
    const suspiciousTlds = [".xyz", ".top", ".buzz", ".work", ".cfd", ".click"];
    if (suspiciousTlds.some(tld => hostname.endsWith(tld))) {
        score += 20;
    }

    // 7. Abnormal length (+10 points if > 75 chars)
    if (fullUrl.length > 75) score += 10;

    const finalScore = Math.min(Math.max(score, 0), 100);

    let decision = "ALLOW";
    if (finalScore >= 75) {
        decision = "BLOCK";
    } else if (finalScore >= 40) {
        decision = "WARN";
    }

    return {
        risk_score: finalScore,
        decision: decision,
        confidence: Number((finalScore / 100).toFixed(2))
    };
}

export default {
    async fetch(request, env, ctx) {
        const corsHeaders = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        };

        if (request.method === "OPTIONS") {
            return new Response(null, { headers: corsHeaders });
        }

        const url = new URL(request.url);
        if (url.pathname === "/api/v1/inspect" && request.method === "POST") {
            try {
                const body = await request.json();
                const targetUrl = body.url;

                if (!targetUrl) {
                    return new Response(
                        JSON.stringify({ error: "Missing 'url' parameter" }),
                        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
                    );
                }

                const assessment = evaluateUrlRisk(targetUrl);

                return new Response(
                    JSON.stringify({
                        url: targetUrl,
                        risk_score: assessment.risk_score,
                        decision: assessment.decision,
                        confidence: assessment.confidence
                    }),
                    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
                );
            } catch {
                return new Response(
                    JSON.stringify({ error: "Invalid JSON payload" }),
                    { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
                );
            }
        }

        return new Response("SentinelGuard Edge Worker Online", {
            status: 200,
            headers: corsHeaders
        });
    }
};