# AtenLana Grid - Environment Variables (Keys)

## Compulsory / must-have (for the app to function correctly)
1. **`DATABASE_URL`**
   - PostgreSQL connection string.
   - Required in practice because the app connects to PostgreSQL using this.
   - Example: `postgresql://user:pass@host:5432/dbname`

2. **`SECRET_KEY`**
   - Flask session/CSRF signing secret.
   - Required for secure sessions (code sets a fallback, but you should always override).

3. **`FLASK_ENV`**
   - Operational environment.
   - Code checks for `FLASK_ENV == 'production'` to enable some production behaviors (e.g., secure cookies, prod upload folder default).

4. **`SUPERADMIN_PASS`**
   - Seeded into the seeded superadmin user password when the DB is initialized.

5. **`ADMIN_PASS`**
   - Seeded into the seeded admin/lecturer credentials during initialization.

## Optional / common environment variables
- **`FLASK_DEBUG`**
  - When `1`, enables debug mode in `app.run()`.

- **`HOST`**
  - Host bind for local runs. Default: `0.0.0.0`.

- **`PORT`**
  - Port for local runs. Default: `5000`.

- **`FORCE_SECURE_COOKIES`**
  - When truthy (`1`), forces secure cookies even if not in production.

- **`UPLOAD_FOLDER`**
  - Overrides where runtime uploads are stored.
  - If empty, code defaults to `/tmp/atenlana_uploads` in production and `static/img` otherwise.

- **`SUPERADMIN_SEED_USER`** / **`SUPERADMIN_SEED_PASS`** / **`SUPERADMIN_SEED_NAME`**
  - Optional bootstrap for creating an extra admin/super-admin from env variables when the DB has no admin yet.
  - Only used if `seed_user` + `seed_pass` are both provided.

- **`PURGE_SAMPLE`**
  - Controls whether the UI route `/admin/purge-samples` will purge sample users/courses.
  - Enable by setting `PURGE_SAMPLE=1`.

## Defaults present in code (in case you omit env vars)
The code contains defaults for:
- `SECRET_KEY` (fallback string)
- `SUPERADMIN_PASS` (defaults to `1234`)
- `ADMIN_PASS` (defaults to `admin123`)
- `FORCE_SECURE_COOKIES` treated as off if unset

However, relying on defaults is unsafe—always set these in real deployments.

