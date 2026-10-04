# FinSecAI — SOC Command Center

A consolidated fraud/security-operations console: FastAPI backend + Next.js frontend,
replacing the earlier collection of Streamlit prototypes with a single deployable app.

## Architecture

```
Next.js frontend (Vercel)
        |
        v
FastAPI backend (Docker: Railway / Render / Fly.io)
        |
        +--> Postgres + pgvector   (incidents, RAG evidence store)
        +--> Redis + workers        (cache, batch scoring, PDF jobs)
        +--> LLM providers          (Claude primary, local model fallback)
```

Frontend deploys to Vercel. Everything else runs as Docker services — long-running
LLM calls, background scoring jobs, and a persistent DB connection don't fit Vercel's
serverless model, so the backend needs a normal container host.

## What's real vs. what's a stub in this skeleton

- **Real**: auth (JWT), incident CRUD, CSV ingestion, the evaluation math (precision/
  recall, fairness, drift, calibration — ported directly from the original metrics
  module), the LLM provider fallback chain, WebSocket streaming for the copilot.
- **Stubbed / demo-quality, flagged in code with `# TODO`**: the RAG retriever returns
  incident-similarity by risk-score bucket rather than real embeddings (drop in
  pgvector + a real embedding model to finish it), ground-truth labels for the
  evaluation tab are synthetic, PDF generation runs synchronously instead of as a
  queued Celery job.

## Running locally

```bash
cp .env.example .env      # fill in at least JWT_SECRET; LLM keys optional (falls back to templated output)
docker compose up -d --build --force-recreate
```

For an existing Postgres database, apply the SQL files in
`backend/migrations_raw_sql/` in numeric order before deploying. New databases
are created automatically by the application. The Docker backend installs the
pinned Python 3.11 ML dependencies and includes the trained synthetic model;
to regenerate it locally, run `python -m app.ml.train` from `backend/` using
an environment with `backend/requirements.txt` installed.

- Frontend: http://localhost:3001
- Backend docs: http://localhost:8001/docs
- Demo login: `demo@finsecai.com` / `demo` (seeded on first boot)

Authentication contexts are separate at the backend boundary:

- `POST /auth/demo/login` accepts only the Acme demo user.
- `POST /auth/tenant/login` accepts only users assigned to an active tenant.
- `POST /auth/owner/login` accepts only the platform owner.
- `POST /auth/credentials` changes the authenticated user's email and password and clears temporary-password state.

If no owner exists, startup creates `owner@finsecai.com` with the bootstrap password
`123` and marks it for credential setup. Existing owner credentials are never reset.
Tenant users provisioned by the owner are marked temporary and must change their
password before entering their tenant console.

## Development workflow

- Use the VS Code tasks for Python and frontend setup.
- Run the backend and frontend through the debugger for the fastest edit loop.

### Refreshing the Docker frontend

`docker compose up -d` deliberately reuses an existing image. After changing
anything in `frontend/`, use **Docker: refresh frontend** from VS Code, or run:

```powershell
docker compose up -d --build --force-recreate frontend
```

The frontend build context excludes `node_modules` and `.next`, so the image is
compiled from the current source instead of a local Next.js cache. Hard-refresh
the browser once after the container has restarted if it has an old document in
its cache.

## Deploying

1. **Frontend** → push `frontend/` to Vercel, set `NEXT_PUBLIC_API_URL` to your backend's
   public URL.
2. **Backend + Postgres + Redis** → deploy `docker-compose.yml`'s backend/db/redis
   services to Railway, Render, or Fly.io. Set the same env vars as `.env.example`.
3. Point the frontend's `NEXT_PUBLIC_API_URL` at the deployed backend and redeploy.

The backend CORS allowlist includes `https://finsec-ai.vercel.app` even when
`CORS_ORIGINS` is set by the hosting provider. Add any additional frontend
custom domains to `CORS_ORIGINS` in the backend environment.

## Project layout

```
backend/app/
  core/         settings, JWT/password handling
  db/           SQLAlchemy models + session
  services/     LLM provider abstraction, intelligence pipeline, evaluation math, PDF reports
  api/routes/   auth, incidents, analytics, copilot (WebSocket), reports
frontend/app/
  login/                    sign-in page
  dashboard/                overview, incidents, incident deep-dive, analytics, copilot
```
