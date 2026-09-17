# VulnSight

Evidence-Based Vulnerability Assessment & Risk Prioritization Platform.

Currently under initial development. See `PLAN_1.md` for the Phase 0 + Phase 1
implementation plan (project foundation, and project/target/scan data model + CRUD).

## Quick Start

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (includes
  Docker Compose). No local Python/Node/Postgres install is required — the
  whole stack runs in containers.

### Run it

```bash
cp .env.example .env
docker compose up --build
```

This starts five services: `postgres`, `redis`, `backend` (FastAPI, hot
reload), `worker` (Celery worker — actually executes scans), and `frontend`
(Next.js dev server, hot reload).

Scans are not run inline by the API process: `POST /scans` enqueues a task
onto `redis` (used here as the Celery broker) and the `worker` service picks
it up and runs the actual port scan (native asyncio-based by default, or
`nmap` if a scan's `config.scanner` is set to `"nmap"`). `nmap` is installed
inside the backend/worker Docker image itself — there's nothing to install
on the host.

The `worker` container does **not** hot-reload on code changes the way
`backend` and `frontend` do. After editing worker/task code, pick the
change up with:

```bash
docker compose restart worker
```

### Apply the database migration

Once the stack is up, run the schema migration **manually**:

```bash
docker compose exec backend alembic upgrade head
```

This is a deliberate manual step, not something run automatically on
container start. If migrations ran automatically at startup and one failed,
the backend container would either crash-loop with an unhelpful error or
silently keep running against a stale/partial schema — either way the
failure is masked behind a generic "container didn't come up" symptom
instead of a clear `alembic upgrade head` error you can act on directly. See
`PLAN_1.md` (Alembic, around line 127) and `PLAN_1_TASKS.md` Task 5 for the
same reasoning.

### URLs

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| Backend API docs (Swagger UI) | http://localhost:8000/docs |
| Backend health check | http://localhost:8000/api/v1/health |

### Verification commands

`backend/requirements.txt` lists runtime-only dependencies; test/lint/type
tooling (pytest, ruff, black, mypy, httpx) lives in
`backend/requirements-dev.txt` — install both for local development or CI
(`pip install -r requirements.txt -r requirements-dev.txt`); the Docker
image already installs both, so the commands below work as-is inside the
container.

Run from `backend/` (inside the container, e.g. `docker compose exec backend
<command>`, or on the host if you have a local Python env set up):

```bash
pytest -v
ruff check .
black --check .
mypy app
```

Run from `frontend/`:

```bash
next lint
```

### Windows-specific notes

1. **`node_modules` anonymous volume is required.** The frontend service in
   `docker-compose.yml` mounts an anonymous volume on `/app/node_modules` on
   top of the bind-mounted source tree. Without it, Windows bind-mounting
   over the container's Linux-built `node_modules` breaks native binaries
   (e.g. `@next/swc`) — don't remove that volume entry.
2. **Line endings.** `.gitattributes` (`* text=auto eol=lf`) normalizes
   checked-out files to LF, which avoids CRLF breaking shell steps and
   Alpine-based images in Docker.
3. **Slow hot reload over Windows bind mounts.** `uvicorn --reload` and the
   Next.js dev server's file-watching can be slow (or occasionally miss
   changes entirely) over Windows bind mounts. If hot reload doesn't fire
   promptly, uncomment the polling fallbacks in `.env`:
   `WATCHFILES_FORCE_POLLING=true` (backend) and `WATCHPACK_POLLING=true`
   (frontend), then restart the stack.
4. **Port collisions.** Ports `5432` (Postgres) and `6379` (Redis) commonly
   collide with an existing local install of either. If `docker compose up`
   fails to bind one of those ports, remap it in `docker-compose.yml`, e.g.
   change `"5432:5432"` to `"5433:5432"` (left side is the host port), and
   update `DATABASE_URL`/`TEST_DATABASE_URL` accordingly if you connect from
   the host.
5. **Save `.env` as UTF-8 without BOM.** Notepad defaults to UTF-8 *with* a
   byte-order mark, which breaks `pydantic-settings`' dotenv parsing (the
   BOM bytes end up prepended to the first variable name). Use an editor
   that lets you choose "UTF-8" (no BOM) explicitly, or `cp .env.example
   .env` as above and edit values without re-saving through Notepad's
   default encoding.
6. **Turbopack route-discovery bug under Windows Docker bind mounts.**
   `frontend/package.json`'s `dev` and `build` scripts both pass
   `--webpack`, forcing the classic webpack bundler instead of Next 16's
   default Turbopack. Without it, a route nested two dynamic segments deep
   under a static path segment (e.g.
   `/projects/[projectId]/scans/[scanId]`) 404s on every request — even on
   a fully cold start with no cache — and the route is missing from
   `next dev`'s own auto-generated `.next/types/routes.d.ts` too, which
   points at a route-discovery bug rather than a dev-server/HMR quirk.
   This matches known upstream Turbopack/Next 16 issues with nested dynamic
   routes on Windows Docker bind mounts (inotify file-watch events not
   propagating into the container). If a future Next/Turbopack upgrade
   fixes this, both `--webpack` flags can likely be dropped — reverify the
   affected route still resolves under Turbopack first.

## Responsible Use

VulnSight is intended strictly for authorized security testing: penetration
tests, security assessments, lab environments, CTFs, and infrastructure you
own or are explicitly permitted to assess. It does not perform autonomous
exploitation.
