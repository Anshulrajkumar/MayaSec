<div align="center">
  <img src="logo.png" alt="MayaSec Logo" width="120" style="border-radius: 20px; margin-bottom: 20px;" />
  <h1>MayaSec - Browser-Side Security Monitoring SDK</h1>
</div>

## v2 Architecture

MayaSec now uses an event-driven architecture across the SDK and backend.

```text
Incoming Event
  -> Validation
  -> Normalization
  -> Rules Engine
  -> Risk Engine
  -> Store
  -> Broadcast Dashboard
  -> Future AI Engine
```

The browser SDK is now organized as:

```text
sdk/
  index.js
  config.js
  logger.js
  storage.js
  utils.js
  transport.js
  events.js
  session.js
  fingerprint.js
  behaviour.js
  auth.js
  api.js
  monitor.js
  rules.js
  risk.js
  deception.js
```

Every module emits standardized security events through the Event Bus:

```javascript
{
  id: "",
  sessionId: "",
  websiteId: "",
  timestamp: "",
  category: "",
  event: "",
  severity: "",
  risk: 0,
  metadata: {}
}
```

**MayaSec** is a lightweight, zero-config JavaScript SDK that adds an invisible security layer to any website. It silently monitors user behavior, fingerprints devices, detects bots, and blocks attacks like SQL Injection — all from the browser, without touching your backend code.

Drop one script tag into your HTML. That's it. Your website is now protected and monitored in real-time through the **MayaSec Command Center**.



---

## What Does MayaSec Do?

| Feature | Description |
|---|---|
| **Device Fingerprinting** | Collects browser name, screen resolution, OS platform, timezone, and language to generate a unique Session ID for every visitor. |
| **Behavioral Telemetry** | Tracks mouse movements (throttled) and click coordinates to build a behavioral profile of each user session. |
| **Bot Detection Engine** | Analyzes click frequency and mouse trajectory patterns in real-time. Flags sessions with non-human behavior (e.g., rapid clicking, zero mouse movement). |
| **SQL Injection Firewall** | Intercepts login form submissions before they reach your server. If a known SQLi payload is detected (e.g., `' OR 1=1--`), the request is **blocked instantly** and an alert is fired. |
| **Real-Time Command Center** | A beautiful dark-mode dashboard that streams all security events live via Server-Sent Events (SSE). Filter events per-website, track active sessions, and monitor threats. |
| **Multi-Site Support** | Monitor multiple websites from a single dashboard. New websites are auto-discovered — no configuration required. |

---

## How to Add MayaSec to Your Website

### Step 1: Add the Script Tag

Paste this snippet inside the `<head>` tag of every HTML page you want to protect:

```html
<!-- MayaSec Security SDK -->
<script type="module" src="https://mayasec.onrender.com/sdk/index.js"></script>
<script type="module">
    import { MayaSec } from 'https://mayasec.onrender.com/sdk/index.js';
    MayaSec.init({ apiKey: 'YOUR_MAYASEC_API_KEY' });
    MayaSec.start();
</script>
```

### Step 2: Create Your Dashboard Account

Sign in to the MayaSec dashboard, generate your API key, and add the domains you want to monitor.

The SDK will silently begin:
- Fingerprinting every visitor's device
- Tracking mouse behavior for bot detection
- Intercepting and blocking SQL Injection attempts on login forms
- Streaming all security telemetry to the MayaSec Command Center

### Step 3: Monitor Your Website

Open the **MayaSec Command Center** to see your website's security data in real-time:

**[https://mayasec.onrender.com](https://mayasec.onrender.com)**

Any allowed website using your API key will appear in the sidebar. Click on it to filter events specific to your site.

---

## Command Center Dashboard

The Command Center is a real-time security monitoring dashboard that gives you full visibility into what's happening on your website(s).

### Features:
- **Multi-Site Sidebar** — All connected websites are listed with live event counters. Click to filter.
- **KPI Cards** — Total Events, Active Sessions, Security Alerts, and Connected Sites at a glance.
- **Live Event Stream** — Every fingerprint, click, mouse movement, and security alert is displayed in real-time with color-coded badges.
- **Threat Highlighting** — Security alerts glow red and pulse to grab your attention.

### Event Types:

| Badge | Meaning |
|---|---|
| 🔵 `session start` | A new visitor connected. Their device fingerprint was captured. |
| 🟡 `behavior batch` | A batch of mouse/click events was received from the visitor. |
| 🟢 `login attempt` | The visitor submitted a login form (clean, no threats detected). |
| 🔴 `SECURITY ALERT` | A threat was detected! Could be SQL Injection, bot behavior, or click spamming. |

---

## Project Architecture

```
MayaSec/
│
├── sdk/                    # Client-side JavaScript SDK (runs in the browser)
│   ├── index.js            # SDK entry point — init(), start(), stop()
│   ├── fingerprint.js      # Device fingerprinting (browser, screen, OS, timezone)
│   ├── behaviour.js        # Mouse tracking, click tracking, bot detection alerts
│   ├── auth.js             # Login form interception & SQL Injection blocking
│   └── transport.js        # Sends telemetry to backend via sendBeacon/fetch
│
├── backend/                # Node.js Express server
│   └── server.js           # API ingestion, bot detection engine, SSE broadcasting
│
├── dashboard/              # Command Center UI
│   └── index.html          # Real-time monitoring dashboard (vanilla HTML/CSS/JS)
│
└── README.md
```

### How It Works (Under the Hood):

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│   Your Website   │────▶│   MayaSec SDK    │────▶│   MayaSec Backend   │
│  (any website)   │     │  (runs silently  │     │  (receives events,  │
│                  │     │   in the browser)│     │   runs bot engine)  │
└─────────────────┘     └──────────────────┘     └────────┬────────────┘
                                                          │
                                                          ▼
                                                 ┌─────────────────────┐
                                                 │   Command Center    │
                                                 │  (live dashboard    │
                                                 │   via SSE stream)   │
                                                 └─────────────────────┘
```

1. The **SDK** is loaded via a `<script>` tag on your website.
2. On page load, it **fingerprints** the visitor's device and sends a `session_start` event.
3. It then silently **tracks** mouse movements and clicks, batching them every 3 seconds.
4. When a login form is submitted, it **inspects** the input for SQL Injection patterns. If found, it **blocks** the submission and fires a `SECURITY_ALERT`.
5. All events are sent to the **MayaSec Backend** via `navigator.sendBeacon()` (non-blocking).
6. The backend runs a **Bot Detection Engine** that analyzes click frequency and mouse trajectory. If suspicious, it generates its own `SECURITY_ALERT`.
7. Events are broadcast to the **Command Center** in real-time via Server-Sent Events (SSE).

---

## Self-Hosting MayaSec

If you want to run your own instance of MayaSec instead of using the hosted version:

### Prerequisites
- Node.js 20+ installed
- npm installed

### Installation

```bash
git clone https://github.com/your-username/MayaSec.git
cd MayaSec
npm install
```

### Running Locally

```bash
npm run dev
```

The server will start on `http://localhost:5000`.

- **Command Center:** `http://localhost:5000/`
- **SDK endpoint:** `http://localhost:5000/sdk/index.js`
- **Ingestion API:** `POST http://localhost:5000/api/ingest`

### Deploying to Render (Recommended)

1. Push this repository to GitHub.
2. Go to [render.com](https://render.com) and create a new **Web Service**.
3. Connect your GitHub repository.
4. Set:
   - **Build Command:** `npm install`
   - **Start Command:** `node backend/server.js`
   - **Environment Variables:** `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, `APP_ORIGIN`
5. Choose the **Free** instance type.
6. Deploy! Your live URL will be your new MayaSec endpoint.

Run the SQL in [docs/supabase.sql](docs/supabase.sql) against your Supabase project before deploying.

Then update the script tag on your websites to point to your Render URL:

```html
<script type="module" src="https://YOUR-APP.onrender.com/sdk/index.js"></script>
<script type="module">
    import { MayaSec } from 'https://YOUR-APP.onrender.com/sdk/index.js';
    MayaSec.init({ apiKey: 'YOUR_MAYASEC_API_KEY' });
    MayaSec.start();
</script>
```

---

## Detection Rules

MayaSec currently implements the following detection rules:

### 1. SQL Injection Detection (Client-Side)
- **Trigger:** User submits a form containing SQL keywords (`SELECT`, `UNION`, `DROP`, `' OR 1=1`, etc.)
- **Action:** Form submission is **blocked**. Browser alert is shown. `SECURITY_ALERT` is sent to the Command Center.
- **Location:** `sdk/auth.js`

### 2. Click Spamming Detection (Server-Side)
- **Trigger:** A behavior batch contains **8+ clicks** within a 3-second window.
- **Action:** `SECURITY_ALERT` is generated and broadcast to the Command Center.
- **Client Warning:** If **10+ clicks** are detected client-side, a browser alert warns the user.
- **Location:** `backend/server.js` (server) and `sdk/behaviour.js` (client)

### 3. Headless Browser / Scripted Bot Detection (Server-Side)
- **Trigger:** A behavior batch contains **clicks but zero mouse movements**.
- **Action:** `SECURITY_ALERT` is generated with "Non-human interaction" classification.
- **Location:** `backend/server.js`

---


## License

This project was built for the **Open Source Contribution to Cyber Security**. 

---

<p align="center">
  <b>MayaSec — Because security shouldn't require a server rewrite.</b>
</p>
