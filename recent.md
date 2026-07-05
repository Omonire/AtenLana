# RECENT.md — Upgrade Coming (GitHub Release Notes)

This release is focused on improving **Vercel stability and correctness by fully supporting PostgreSQL** (via `DATABASE_URL`).

## What’s being upgraded

### 1) PostgreSQL-first database layer (Vercel-ready)
- Added/updated **database connectivity using `psycopg2`**.
- Introduced `get_database_url()` with Vercel compatibility:
  - Uses `DATABASE_URL` (preferred)
  - Falls back to `POSTGRES_URL`.
- Improved serverless behavior:
  - **Lazy initialization** (`init_db()` runs on first request to reduce cold-start timeouts).
  - Connection attempts use short timeouts and a small retry window.

### 2) DB query compatibility between SQLite-style and PostgreSQL placeholders
- `query_db()` and `commit_db()` now convert SQLite-style `?` placeholders into PostgreSQL `%s` placeholders.
- `INSERT OR IGNORE` patterns are normalized for PostgreSQL compatibility.

### 3) PostgreSQL schema migration & idempotent initialization
- `init_db()` now creates tables using PostgreSQL syntax (e.g., `SERIAL`, `NOW()`, `TIMESTAMP`).
- Added idempotent migrations:
  - `CREATE TABLE IF NOT EXISTS ...`
  - `ALTER TABLE ... ADD COLUMN IF NOT EXISTS ...`
  - PostgreSQL `DO $$ ... $$` blocks for constraint/index idempotency.

### 4) Vercel serverless entry handler
- Added `serverless_wsgi` handler so the Flask app can run correctly in Vercel’s serverless runtime.

### 5) Related fixes already aligned to the upgrade
- Timestamp and timezone handling improvements used across the session/token attendance flow.
- Health endpoint (`/health`) verifies database connectivity.

## Required environment variables (for this upgrade)
- `DATABASE_URL` (PostgreSQL DSN)
- `SECRET_KEY`
- `FLASK_ENV=production` (recommended for production behavior)
- `SUPERADMIN_PASS` and `ADMIN_PASS`

## How to use this file
This document is intended to be used as **GitHub Release notes** for your next deployment/update.
