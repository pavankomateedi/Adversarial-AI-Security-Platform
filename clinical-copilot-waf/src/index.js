/**
 * Clinical Co-Pilot WAF — a Cloudflare Worker that sits in front of the
 * deployed OpenEMR Clinical Co-Pilot as a filtering reverse proxy.
 *
 * This is the "traditional security tooling" layer the PRD calls for: a
 * network-edge firewall, distinct from AgentForge's adversarial testing.
 * It runs on Cloudflare's edge for free (Workers free tier: 100k req/day),
 * needs no custom domain, and proxies every request to the real Co-Pilot
 * only after it passes the rule set below.
 *
 * Layers (request rejected at the first one that trips):
 *   1. Geo-blocking          — block traffic from countries you don't serve
 *   2. Scanner user-agents   — sqlmap / nikto / nuclei / etc.
 *   3. Cloudflare threat score — built-in bot/abuse signal, free per request
 *   4. Body-size cap         — reject payloads over MAX_BODY_BYTES
 *   5. Injection patterns    — SQLi / XSS / path traversal in URL + body
 *   6. Per-IP rate limiting  — sliding window via Workers KV
 *   7. Proxy + harden        — forward clean requests, add security headers
 *
 * IMPORTANT: this WAF is a *compensating control*. It cannot stop broken
 * object-level authorization (the VULN-001/002/003 class AgentForge found)
 * — those requests are syntactically perfect. It DOES shrink the attack
 * surface: injection classes, enumeration via rate-limiting, DoS, scanners.
 */

const SCANNER_UA = /(sqlmap|nikto|gobuster|dirbuster|wpscan|nessus|acunetix|nuclei|metasploit|hydra|burpcollab|fuzz)/i;

const SQLI = [
  /\b(union\s+(all\s+)?select|select\s+.*\s+from|insert\s+into|drop\s+table|drop\s+database)\b/i,
  /(--\s*$|;\s*--|\/\*.*\*\/|\bxp_cmdshell\b|\bexec\s*\(|\bload_file\s*\()/i,
  /\b(or|and)\s+\d+\s*=\s*\d+\b/i,
];
const XSS = [
  /<script[\s>]/i,
  /javascript:\s*[^/]/i,
  /\bon(error|load|click|mouseover)\s*=/i,
];
const TRAVERSAL = /(\.\.[/\\]|%2e%2e[/\\]|%252e%252e)/i;

function scanText(text) {
  for (const p of SQLI) if (p.test(text)) return "sqli_pattern";
  for (const p of XSS) if (p.test(text)) return "xss_pattern";
  if (TRAVERSAL.test(text)) return "path_traversal";
  return null;
}

function block(code, detail, extra = {}) {
  console.log(JSON.stringify({ waf_block: true, code, detail, ...extra }));
  return new Response(
    JSON.stringify({ detail, blocked_by: "clinical-copilot-waf", code }),
    { status: code, headers: { "content-type": "application/json" } },
  );
}

/** Sliding-window rate limit via Workers KV. Gracefully no-ops if KV unbound. */
async function rateLimited(env, ip, path) {
  if (!env.RATE_LIMIT_KV) return false; // KV not configured — skip, don't fail
  // Stricter limits on the sensitive write paths.
  const perMinute =
    path.startsWith("/auth/login") ? 10 :
    path.startsWith("/chat") ? 30 :
    60;
  const windowKey = `rl:${ip}:${Math.floor(Date.now() / 60000)}`;
  const current = parseInt((await env.RATE_LIMIT_KV.get(windowKey)) || "0", 10);
  if (current >= perMinute) return { limit: perMinute, current };
  // KV writes are eventually-consistent; fine for best-effort rate limiting.
  await env.RATE_LIMIT_KV.put(windowKey, String(current + 1), { expirationTtl: 120 });
  return false;
}

function hardenHeaders(resp) {
  // Re-wrap so we can mutate headers on an immutable upstream response.
  const h = new Headers(resp.headers);
  h.set("X-Content-Type-Options", "nosniff");
  h.set("X-Frame-Options", "DENY");
  h.set("Referrer-Policy", "strict-origin-when-cross-origin");
  h.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  h.set("X-WAF", "clinical-copilot-waf");
  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers: h });
}

export default {
  async fetch(request, env, _ctx) {
    const url = new URL(request.url);
    const target = env.TARGET_URL || "https://web-production-6259a.up.railway.app";
    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    const ua = request.headers.get("user-agent") || "";
    const cf = request.cf || {};
    const country = cf.country || "XX";
    const path = url.pathname;

    // 1. Geo-blocking. BLOCKED_COUNTRIES is a comma-separated env var, e.g.
    //    "KP,RU" — empty by default (allow all).
    const blocked = (env.BLOCKED_COUNTRIES || "").split(",").map(s => s.trim()).filter(Boolean);
    if (blocked.includes(country)) {
      return block(403, `Geo-blocked: ${country}`, { ip, country });
    }

    // 2. Scanner user-agents.
    if (SCANNER_UA.test(ua)) {
      return block(403, "Scanner user-agent rejected", { ip, ua: ua.slice(0, 80) });
    }

    // 3. Cloudflare threat score (0 = clean, 100 = known-bad). Free per request.
    if (typeof cf.threatScore === "number" && cf.threatScore > 50) {
      return block(403, "High Cloudflare threat score", { ip, threatScore: cf.threatScore });
    }

    // 4. Body-size cap.
    const MAX_BODY_BYTES = parseInt(env.MAX_BODY_BYTES || "51200", 10); // 50 KB
    const contentLength = parseInt(request.headers.get("content-length") || "0", 10);
    if (contentLength > MAX_BODY_BYTES) {
      return block(413, `Payload too large (${contentLength} > ${MAX_BODY_BYTES})`, { ip });
    }

    // 5. Injection scan — query string always; body for write methods.
    const decodedQs = decodeURIComponent(url.search);
    let reason = decodedQs ? scanText(decodedQs) : null;
    if (reason) return block(400, `Request blocked: ${reason} in query`, { ip, path });

    let bodyText = null;
    if (["POST", "PUT", "PATCH"].includes(request.method)) {
      // Read once, scan, then forward the same bytes.
      bodyText = await request.text();
      if (bodyText) {
        reason = scanText(bodyText);
        if (reason) return block(400, `Request blocked: ${reason} in body`, { ip, path });
      }
    }

    // 6. Per-IP rate limiting.
    const rl = await rateLimited(env, ip, path);
    if (rl) {
      return new Response(
        JSON.stringify({ detail: "Rate limit exceeded", blocked_by: "clinical-copilot-waf", ...rl }),
        { status: 429, headers: { "content-type": "application/json", "Retry-After": "60" } },
      );
    }

    // 7. Proxy clean request to the Co-Pilot, then harden the response.
    const upstreamUrl = target.replace(/\/$/, "") + path + url.search;
    const upstreamReq = new Request(upstreamUrl, {
      method: request.method,
      headers: request.headers,
      body: bodyText !== null ? bodyText : request.body,
      redirect: "manual",
    });
    let upstream;
    try {
      upstream = await fetch(upstreamReq);
    } catch (e) {
      return block(502, `Upstream unreachable: ${e.message}`, { ip, target });
    }
    return hardenHeaders(upstream);
  },
};
