# AtenLana-Grid Deployment Guide // Vercel Protocol
> **"Leave No One Behind" Strategy**
> *Ensuring absolute modular integrity across the Vercel serverless lattice.*

## [0x01] Introduction
This guide outlines the mandatory steps to deploy the **AtenLana-Grid** ecosystem to Vercel. To maintain the "Zero-Proxy" integrity of the grid, the deployment must ensure that every functional module—from spatial kernels to identity helpers—is correctly bundled and accessible to the serverless entry point.

## [0x02] The "Zero-Loss" File Architecture
Vercel's Python runtime requires that all local modules imported by the application are part of the deployment bundle. To prevent `ModuleNotFoundError`, the project has been structured to ensure "no one is left behind."

### Essential File Checklist:
- `index.py`: The Primary Lattice Entry Point (Root).
- `auth_helpers.py`: Identity Fingerprinting & Security Handshakes.
- `location.py`: Haversine Spatial Telemetry Kernels.
- `seed_data.py`: Mandatory Identity Matrix Seeding.
- `requirements.txt`: Dependency Manifest.
- `vercel.json`: Deployment Routing Logic.
- `templates/`: UI Layer (Auto-bundled).
- `static/`: Asset Layer (Served via routing).

---

## [0x03] Mandatory Environment Variables
Before deploying, the following variables must be configured in the Vercel Dashboard to establish the PostgreSQL lattice:

| Variable | Description | Example |
| :--- | :--- | :--- |
| `DATABASE_URL` | PostgreSQL DSN Connection String | `postgresql://user:pass@host:port/db` |
| `SECRET_KEY` | Encrypted Handshake Key | `[SECURE_RANDOM_STRING]` |
| `FLASK_ENV` | Operational Environment | `production` |
| `SUPERADMIN_PASS` | Root Access Credential | `[YOUR_SECURE_PASSWORD]` |
| `ADMIN_PASS` | Admin Cluster Credential | `[YOUR_SECURE_PASSWORD]` |

---

## [0x04] Environment Template
An example environment configuration is provided in `.env.example`. You can use this as a reference when adding variables to the Vercel dashboard.

---

## [0x05] Deployment Sequence
1. **GitHub Integration**: Connect your repository to Vercel.
2. **Detection**: Vercel will auto-detect the `vercel.json` configuration.
3. **Project Settings**:
   - **Build Command**: Leave **Empty** (Vercel handles this via the `@vercel/python` builder).
   - **Install Command**: Leave **Empty** (Vercel automatically installs `requirements.txt`).
   - **Output Directory**: Leave **Empty**.
4. **Build Execution**: The builder installs dependencies and prepares the serverless functions.
5. **Initialization**: On first boot, the system will execute `init_db()` in `api/index.py`, establishing the PostgreSQL schema.

## [0x06] Post-Deployment Verification
Once the grid is active, verify the following nodes:
1. **Health Check**: Visit `/health` to ensure the PostgreSQL connection is stable.
2. **Infrastructure Pulse**: Log in as Superadmin and visit `/superadmin/deployment` to verify environment variable synchronization.
3. **Identity Check**: Ensure the default identity clusters (Admin, Founder) are seeded in the Identity Vault.

---
© 2026 AtenLana Technology. *Where Integrity Meets Attendance.*
