# MayaSec SDK

MayaSec is a standalone JavaScript SDK scaffold for browser-side security monitoring. It is designed to be integrated into any website later with a single `<script>` tag, while keeping SDK code, backend services, dashboard assets, documentation, and examples separated.

This initialization contains project structure and boilerplate only. Monitoring, analytics, network interception, fingerprinting, and backend persistence logic are intentionally not implemented yet.

## Folder Structure

- `sdk/` - Browser SDK modules and public entry point.
- `backend/` - Minimal Express backend placeholder for future event ingestion.
- `backend/routes/` - Route definitions for future backend APIs.
- `backend/controllers/` - Request handlers for future backend APIs.
- `backend/middleware/` - Shared backend middleware.
- `backend/database/` - Future database connection and schema modules.
- `backend/services/` - Backend service layer modules.
- `dashboard/` - Future administrative dashboard.
- `docs/` - Technical documentation and integration guides.
- `examples/securebank/` - Future SecureBank integration example.

## Installation

```bash
npm install
```

## Development

Start the backend in development mode:

```bash
npm run dev
```

Start the backend normally:

```bash
npm start
```

The backend runs on port `5000` and responds at `/` with:

```text
MayaSec Backend Running
```

## Roadmap

- Build browser event collection for authentication, API usage, behavior, fingerprinting, and client-side security signals.
- Add secure batching, retry queues, and transport hardening.
- Implement backend ingestion, validation, storage, and alerting.
- Build a dashboard for risk events, sessions, users, and integrations.
- Add integration guides for single-script usage in existing websites.
- Integrate with Zeek, Suricata, Cowrie, OpenCanary, Heralding, and MITRE ATT&CK mappings for future detection, enrichment, and threat intelligence workflows.

