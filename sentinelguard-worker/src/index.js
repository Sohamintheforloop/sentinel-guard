const SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "banking", "wallet", "signin", "password", "confirm"
];

// --- TIER 1: Local Heuristics ---
function evaluateUrlRisk(urlString) {
    let url;
    try {
        url = new URL(urlString);
    } catch {
        return { risk_score: 50, decision: "WARN", confidence: 0.5, details: "Malformed URL" };
    }

    const hostname = url.hostname.toLowerCase();
    const pathname = url.pathname.toLowerCase();
    const fullUrl = url.href.toLowerCase();
    let score = 0;

    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) score += 40;
    if (fullUrl.includes("@")) score += 35;

    const domainParts = hostname.split(".");
    const subdomainCount = Math.max(0, domainParts.length - 2);
    score += Math.min(subdomainCount * 12, 30);

    const hyphenCount = (hostname.match(/-/g) || []).length;
    score += Math.min(hyphenCount * 6, 24);

    let keywordHits = 0;
    const targetString = `${hostname}${pathname}`;
    for (const kw of SUSPICIOUS_KEYWORDS) {
        if (targetString.includes(kw)) keywordHits++;
    }
    score += Math.min(keywordHits * 15, 45);

    const suspiciousTlds = [".xyz", ".top", ".buzz", ".work", ".cfd", ".click"];
    if (suspiciousTlds.some(tld => hostname.endsWith(tld))) score += 20;
    if (fullUrl.length > 75) score += 10;

    const finalScore = Math.min(Math.max(score, 0), 100);
    let decision = "ALLOW";
    if (finalScore >= 75) decision = "BLOCK";
    else if (finalScore >= 30) decision = "WARN";

    return {
        risk_score: finalScore,
        decision: decision,
        confidence: Number((finalScore / 100).toFixed(2)),
        details: "Local heuristic evaluation"
    };
}

// --- TIER 2: Groq AI Analyst ---
async function askGroqAnalyst(targetUrl, apiKey) {
    const prompt = `You are an expert cybersecurity system. Analyze this URL for phishing, homoglyphs, brand spoofing, and malicious patterns: "${targetUrl}". 
    Return ONLY a JSON object. Do not include markdown formatting.
    Format required:
    {
        "risk_score": <integer 0-100>,
        "decision": "<ALLOW, WARN, or BLOCK>",
        "details": "<brief 1-sentence explanation>"
    }`;

    try {
        const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${apiKey}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                model: "llama-3.3-70b-versatile", // Fast, highly capable model
                messages: [
                    { role: "system", content: "You output only raw JSON." },
                    { role: "user", content: prompt }
                ],
                response_format: { type: "json_object" }, // Forces valid JSON output
                temperature: 0.1 // Low temperature for consistent, analytical responses
            })
        });

        if (!res.ok) return null; // Fails safely

        const data = await res.json();
        const content = data.choices[0].message.content;
        return JSON.parse(content);
    } catch (err) {
        return null; // If Groq times out or fails, we fall back to math
    }
}

// --- CLOUDFLARE WORKER ROUTING ---
export default {
    async fetch(request, env, ctx) {
        const corsHeaders = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
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

                // Run Tier 1
                let assessment = evaluateUrlRisk(targetUrl);

                // Run Tier 2 if the URL looks slightly suspicious AND we have a Groq key
                if (assessment.risk_score >= 30 && env.GROQ_API_KEY) {
                    const groqResult = await askGroqAnalyst(targetUrl, env.GROQ_API_KEY);

                    if (groqResult && typeof groqResult.risk_score === "number") {
                        // Override math with AI expertise
                        assessment.risk_score = groqResult.risk_score;
                        assessment.decision = groqResult.decision || (groqResult.risk_score >= 75 ? "BLOCK" : "WARN");
                        assessment.confidence = 0.95;
                        assessment.details = `AI Analysis: ${groqResult.details || "Flagged by LLM"}`;
                    }
                }

                return new Response(
                    JSON.stringify({
                        url: targetUrl,
                        risk_score: assessment.risk_score,
                        decision: assessment.decision,
                        confidence: assessment.confidence,
                        details: assessment.details
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
            headers: { ...corsHeaders, "Content-Type": "text/plain" }
        });
    }
};