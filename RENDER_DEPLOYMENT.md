# Render Production Deployment Guide

This guide outlines the step-by-step instructions to deploy the **SOC Sentinel XDR Incident Response Platform** onto **Render** using the pre-configured Infrastructure-as-Code (`render.yaml`) blueprint.

---

## 🏗️ Production Architecture on Render

The platform is configured to run in production with:
1. **Web Service**: Powered by **Gunicorn** (WSGI HTTP server) serving the Flask application (`run:app`).
2. **Database Service**: A managed **PostgreSQL** instance automatically linked to the Web service via the secure private network connection string (`DATABASE_URL`).
3. **Persistent Volume (Disk)**: A 1 GB persistent disk mounted at `/opt/render/project/src/app/static/uploads`. This preserves:
   - Generated PDF reports.
   - Analyst notes screenshots/attachments.
   - Raw parsed files (logs stored under `/opt/render/project/src/app/static/uploads/logs`).
   
*Note: Because Render's container filesystems are ephemeral, mounting the disk directly under the `static/uploads/` path ensures all files uploaded or compiled by analysts persist across deployments and daily container restarts.*

---

## 📋 Pre-Deployment Commands (Important)

If you are developing on a Windows machine, Git may not save the execute permissions for the build script. Run the following command in your terminal **before committing and pushing your code** to ensure Render's build agent has permission to execute `build.sh`:

```bash
git update-index --chmod=+x build.sh
```

---

## 🚀 Deployment Steps (Render Blueprint)

Render's Blueprint feature reads the `render.yaml` file in your repository and provisions all databases, services, disks, and environment variables automatically.

### Step 1: Connect GitHub / GitLab to Render
1. Log in to your [Render Dashboard](https://dashboard.render.com).
2. Click **New** (top right) and select **Blueprint**.
3. Connect your Git repository (GitHub/GitLab) where this project is hosted.

### Step 2: Deploy Blueprint Services
1. Once connected, Render will parse the `render.yaml` configuration.
2. Provide a **Group Name** (e.g., `soc-sentinel-group`).
3. Click **Apply**. Render will automatically begin provisioning:
   - **soc-sentinel-db** (PostgreSQL database instance).
   - **soc-sentinel-uploads** (1 GB Persistent Disk).
   - **soc-sentinel-xdr** (Web application service running Gunicorn).

### Step 3: Automated Initialization (Release Phase)
During the build command execution, Render runs `build.sh` which:
- Installs all dependencies.
- Sets up directory structures inside the persistent disk volume.
- Executes `init_db.py` to create the PostgreSQL tables and auto-seed default Super Admin (`admin`), Analyst (`analyst`), and Viewer (`viewer`) accounts (if not already seeded).

### Step 4: Access Your Live Instance
Once the logs show `State: active`, your application is live. 
1. Navigate to the Web Service URL provided by Render (e.g., `https://soc-sentinel-xdr.onrender.com`).
2. Log in using the default Super Admin credentials:
   - **Username**: `admin`
   - **Password**: `SentinelXDR2026!`
3. Make sure to update the passwords or add custom analysts using the **User Provisioning** page in production.

---

## 🔍 Health Checks & Telemetry

Render is configured to perform automated health checks during rolling updates and hosting cycles.
- **Endpoint**: `https://<your-subdomain>.onrender.com/health`
- **Response Format** (JSON):
  ```json
  {
    "status": "healthy",
    "database": "connected",
    "timestamp": "2026-06-23T12:00:00.000000"
  }
  ```
If the database connection drops or a query fails, the endpoint returns status code `500` with detailed error telemetry.

---

## ⚙️ Manual Deployment (Alternative to Blueprints)

If you prefer not to use Render Blueprints, you can create the services manually:

1. **Create PostgreSQL Database**:
   - Name: `soc-sentinel-db`
   - Plan: Free (or higher)
   - Copy the **Internal Database URL**.
2. **Create Web Service**:
   - Runtime: `Python`
   - Build Command: `./build.sh`
   - Start Command: `gunicorn run:app`
   - **Environment Variables**:
     - `DATABASE_URL`: (Paste the Internal Database URL from step 1)
     - `SECRET_KEY`: (Enter a secure, long random string)
     - `UPLOAD_FOLDER`: `/opt/render/project/src/app/static/uploads/logs`
     - `PYTHON_VERSION`: `3.11.8`
   - **Disks**:
     - Add Disk.
     - Mount Path: `/opt/render/project/src/app/static/uploads`
     - Size: `1 GB`
3. Click **Deploy Web Service**.
