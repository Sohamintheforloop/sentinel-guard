import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from './index.js';

describe('SentinelGuard API Tests', () => {
    it('Scores PayPal phishing URL as BLOCK', async () => {
        const request = new Request('http://localhost/api/v1/inspect', {
            method: 'POST',
            body: JSON.stringify({ url: "http://secure-login-paypal.phishsite.xyz/update" })
        });
        const ctx = createExecutionContext();
        const response = await worker.fetch(request, env, ctx);
        await waitOnExecutionContext(ctx);

        const data = await response.json();
        expect(data.decision).toBe('BLOCK');
        expect(data.risk_score).toBeGreaterThanOrEqual(75);
    });

    it('Scores Google as ALLOW', async () => {
        const request = new Request('http://localhost/api/v1/inspect', {
            method: 'POST',
            body: JSON.stringify({ url: "https://www.google.com" })
        });
        const ctx = createExecutionContext();
        const response = await worker.fetch(request, env, ctx);
        await waitOnExecutionContext(ctx);

        const data = await response.json();
        expect(data.decision).toBe('ALLOW');
        expect(data.risk_score).toBeLessThan(40);
    });
});