# Panel static assets (Phase 3+)

Phase 0 ships only `robots.txt`. The SPA shell (`index.html`, `wizard.html`,
`dashboard.html`) and the Alpine.js app bundle land here in Phase 3/6 — see
[`../plans/ROADMAP.md`](../plans/ROADMAP.md) §4 file layout.

Phase 6 added [`dashboard.html`](dashboard.html) — a self-contained
Alpine.js + Pico.css SPA shell that drives the `/api/dashboard/*` handlers
(see [`../dashboard/router.py`](../dashboard/router.py)). `main.py` serves it
at the convenience route `GET /dashboard`. It pulls Alpine and Pico from jsdelivr
CDN at runtime; no build step is required.

The build picks up everything under `panel/static/**` via
`[tool.setuptools.package-data]` in [`panel/pyproject.toml`](../panel/pyproject.toml).
