# WebsiteFix

Minimal, open-source website auditing tool. Monochrome frontend and dependency-free Python HTTP backend.

## Run locally

```bash
python app.py
```

Open http://127.0.0.1:8000. `GET /health` provides a health check. `POST /api/scan` accepts `{"url":"https://example.org"}`.

## Included

- Live HTML page scanning with IP-pinned outbound HTTP(S)
- Title, description, H1, viewport, language, image alt and HTTPS/CSP checks
- Evidence-based findings and a **heuristic** score
- JSON report download
- Basic in-process rate limits and concurrency controls
- Minimal responsive frontend and Dockerfile

## Production limitations

**This is an unverified beta, not a production-certified service.** Live external site scans, public hosting, distributed abuse controls, and penetration testing are not yet verified. Scans are HTML-only, without JavaScript rendering or Lighthouse. No authentication, billing, PDF export, persistent storage or scheduling is implemented. Before internet exposure, add infrastructure egress restrictions, monitoring, global rate limits and a security review.

MIT licensed.
