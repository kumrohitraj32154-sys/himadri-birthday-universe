// Cloudflare Pages Server-Side Authentication Middleware
// Protects index.html, images, music, letter, and all static assets.

const COOKIE_NAME = "himadri_universe_session";
const SESSION_DURATION_SECONDS = 60 * 60 * 24 * 7; // 7 days session

async function sha256Hex(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hmacSign(message, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(";").forEach((part) => {
    const [k, ...v] = part.trim().split("=");
    if (k) cookies[k] = v.join("=");
  });
  return cookies;
}

async function createSessionToken(secret) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_DURATION_SECONDS;
  const payload = `authenticated.${exp}`;
  const sig = await hmacSign(payload, secret);
  return `${payload}.${sig}`;
}

async function verifySessionToken(token, secret) {
  if (!token || !secret) return false;
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [status, expStr, sig] = parts;
  if (status !== "authenticated") return false;
  const exp = parseInt(expStr, 10);
  if (isNaN(exp) || Math.floor(Date.now() / 1000) > exp) return false;
  const expectedSig = await hmacSign(`${status}.${expStr}`, secret);
  return timingSafeEqual(sig, expectedSig);
}

function getLoginPageHTML(errorMessage = "") {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>The Universe on Your Day</title>
  <meta name="robots" content="noindex, nofollow" />
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: radial-gradient(ellipse at bottom, #1b2735 0%, #090a0f 100%);
      color: #ffffff;
      font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      padding: 20px;
      overflow: hidden;
    }
    .stars {
      position: fixed;
      inset: 0;
      background-image:
        radial-gradient(2px 2px at 20px 30px, #eee, rgba(0,0,0,0)),
        radial-gradient(2px 2px at 40px 70px, #fff, rgba(0,0,0,0)),
        radial-gradient(1px 1px at 90px 40px, #fff, rgba(0,0,0,0)),
        radial-gradient(2px 2px at 160px 120px, #ddd, rgba(0,0,0,0));
      background-repeat: repeat;
      background-size: 200px 200px;
      opacity: 0.45;
      pointer-events: none;
    }
    .card {
      position: relative;
      z-index: 2;
      width: 100%;
      max-width: 400px;
      background: rgba(15, 20, 35, 0.78);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      border: 1px solid rgba(255, 255, 255, 0.14);
      border-radius: 20px;
      padding: 38px 28px;
      text-align: center;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6);
    }
    .icon {
      font-size: 36px;
      margin-bottom: 14px;
      display: inline-block;
    }
    h1 {
      font-size: 1.55rem;
      font-weight: 600;
      letter-spacing: 0.5px;
      margin-bottom: 10px;
      background: linear-gradient(90deg, #fff, #c9d6ff);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    p.subtitle {
      font-size: 0.94rem;
      color: #a9b6d3;
      line-height: 1.5;
      margin-bottom: 26px;
    }
    form {
      display: flex;
      flex-direction: column;
      gap: 14px;
    }
    input[type="password"] {
      width: 100%;
      padding: 14px 16px;
      border-radius: 12px;
      border: 1px solid rgba(255, 255, 255, 0.22);
      background: rgba(255, 255, 255, 0.07);
      color: #fff;
      font-size: 1rem;
      text-align: center;
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    input[type="password"]:focus {
      border-color: #9bb8ff;
      box-shadow: 0 0 14px rgba(155, 184, 255, 0.28);
    }
    button {
      width: 100%;
      padding: 14px;
      border-radius: 12px;
      border: none;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: #fff;
      font-size: 1rem;
      font-weight: 600;
      letter-spacing: 0.4px;
      cursor: pointer;
      transition: transform 0.15s, opacity 0.2s;
    }
    button:active {
      transform: scale(0.98);
    }
    .error {
      margin-top: 14px;
      padding: 10px 12px;
      border-radius: 8px;
      background: rgba(255, 82, 82, 0.16);
      border: 1px solid rgba(255, 82, 82, 0.4);
      color: #ffb3b3;
      font-size: 0.88rem;
    }
  </style>
</head>
<body>
  <div class="stars"></div>
  <div class="card">
    <div class="icon">✨</div>
    <h1>The Universe on Your Day</h1>
    <p class="subtitle">A private cosmos awaits. Enter the secret password to enter.</p>
    <form method="POST" action="/__unlock">
      <input type="password" name="password" placeholder="Enter secret password" required autofocus autocomplete="current-password" />
      <button type="submit">Unlock the Universe</button>
    </form>
    ${errorMessage ? `<div class="error">${errorMessage}</div>` : ""}
  </div>
</body>
</html>`;
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  // Enforce HTTPS on production
  if (url.protocol === "http:" && url.hostname !== "localhost" && url.hostname !== "127.0.0.1") {
    url.protocol = "https:";
    return Response.redirect(url.toString(), 301);
  }

  const configuredPassword = env.SITE_PASSWORD;
  const sessionSecret = env.SESSION_SECRET || (configuredPassword ? configuredPassword + "_hmac_key" : "");

  // Fail-closed security: If password isn't configured in Cloudflare yet, block all access
  if (!configuredPassword) {
    return new Response(
      getLoginPageHTML("Site protection is active. Waiting for administrator to set SITE_PASSWORD in Cloudflare settings."),
      {
        status: 503,
        headers: {
          "Content-Type": "text/html; charset=UTF-8",
          "Cache-Control": "no-store, no-cache, must-revalidate",
        },
      }
    );
  }

  // Handle login form submission
  if (url.pathname === "/__unlock" && request.method === "POST") {
    try {
      const formData = await request.formData();
      // Normalize spaces and case so mobile keyboard auto-cap or trailing space doesn't lock her out
      const submittedPassword = (formData.get("password") || "").toString().trim().toLowerCase();
      const normalizedConfigured = configuredPassword.toString().trim().toLowerCase();

      // Compare SHA-256 hashes in constant time
      const submittedHash = await sha256Hex(submittedPassword);
      const expectedHash = await sha256Hex(normalizedConfigured);

      if (timingSafeEqual(submittedHash, expectedHash)) {
        const token = await createSessionToken(sessionSecret);
        return new Response(null, {
          status: 302,
          headers: {
            "Location": "/",
            "Set-Cookie": `${COOKIE_NAME}=${token}; Path=/; Max-Age=${SESSION_DURATION_SECONDS}; HttpOnly; Secure; SameSite=Lax`,
            "Cache-Control": "no-store",
          },
        });
      } else {
        // Delay 1 second on failed attempt to slow down brute-force guessing
        await new Promise((r) => setTimeout(r, 1000));
        return new Response(
          getLoginPageHTML("Incorrect password. Please try again."),
          {
            status: 401,
            headers: {
              "Content-Type": "text/html; charset=UTF-8",
              "Cache-Control": "no-store",
            },
          }
        );
      }
    } catch (e) {
      return new Response(getLoginPageHTML("Invalid request. Please try again."), {
        status: 400,
        headers: { "Content-Type": "text/html; charset=UTF-8" },
      });
    }
  }

  // Verify session cookie on EVERY request (HTML, images, audio, letter, etc.)
  const cookies = parseCookies(request.headers.get("Cookie"));
  const token = cookies[COOKIE_NAME];
  const isAuthenticated = await verifySessionToken(token, sessionSecret);

  if (!isAuthenticated) {
    return new Response(getLoginPageHTML(), {
      status: 401,
      headers: {
        "Content-Type": "text/html; charset=UTF-8",
        "Cache-Control": "no-store, no-cache, must-revalidate",
      },
    });
  }

  // Authenticated: serve the requested asset and prevent public caching
  const response = await next();
  const newHeaders = new Headers(response.headers);
  newHeaders.set("Cache-Control", "private, no-cache");
  newHeaders.set("X-Robots-Tag", "noindex, nofollow");

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders,
  });
}
