# SOC Sentinel XDR - Incident Response Platform

SOC Sentinel XDR is an advanced, responsive, and role-secured cybersecurity Log Analysis, Threat Detection, and Incident Response Platform. It allows security teams to ingest logs, extract threat indicators (IOCs), declare security incidents, collaborate on case files using Markdown notes, view system audit trails, and compile compliance PDF reports with native visualization charts.

---

## 🚀 Key Features

### 1. Correlated Threat Detection & Log Ingestion
- Ingest and analyze syslog files (`.txt`, `.csv`, `.log`).
- Automatic parsing of authentication events, matching them against local Threat Intelligence databases (IOCs).
- IP Geo-location tagging (Country and City lookups).
- Automated MITRE ATT&CK Matrix mapping (Tactics & Techniques alignment).

### 2. Incident Management Workspace
- Transition correlated alerts into formal incidents with a single click (**Escalate**).
- Manage incident parameters including severity levels (Low, Medium, High, Critical) and investigation status (Open, Investigating, Resolved, Closed).
- Automatic chronological event logging (**Incident Timeline**) recording status updates, reassignments, and notes addition.

### 3. Investigation Notes (Markdown & Screenshot Attachments)
- Post case investigation updates supporting rich **Markdown formatting** (headers, bold text, lists, code snippets).
- Client-side **Live Markdown Preview** powered by `marked.js` inside the editor.
- Attach evidence screenshots directly to notes. Image files are validated, securely stored under `app/static/uploads/screenshots/`, and displayed inline.

### 4. Dynamic PDF Report Generator
- Generate PDF compliance reports using `reportlab`:
  - **Daily SOC Report** (24h alert counts, status, and severity distributions).
  - **Threat Summary Report** (Global platform metrics and top attacking source IPs).
  - **IOC Match Report** (Threat intelligence matching history).
  - **Incident Investigation Report** (Detailed single-case summary with description, notes, and full timeline history).
- **Watermark:** Embeds a diagonal **`SOC Sentinel XDR` / `CONFIDENTIAL`** watermark across all PDF pages.
- **Charts:** Draws native vector graphics (Severity Pie Charts, Alert Category Bar Charts, IP Occurrence Bar Charts) directly into the reports.
- Automatically compiles database summaries to prefill draft sections.

### 5. Cryptographic Audit Trail
- Log and track system actions:
  - Logins (Successful and Failed attempts) and Logouts.
  - Alert actions (Acknowledge, Resolve, False Positive, Assign).
  - Incident actions (Created, severity/status modifications, notes posted).
  - Administrative actions (User provisioning/deprovisioning).
- Accessible exclusively by Super Admins.

### 6. Role-Based Access Control (RBAC)
Normalised platform access into three distinct user roles:
- **Super Admin (`admin`)**: Complete platform permissions. Can provision accounts, view audit trails, declare/edit incidents, write notes, and compile PDF reports.
- **SOC Analyst (`analyst`)**: Read-write access. Can declare/edit incidents, write notes with screenshot evidence, and generate PDF reports. Restricted from IAM provisioning and viewing audit trails.
- **Viewer (`viewer`)**: Read-only access. Can read dashboards, alerts, incidents, notes, and previous reports. Cannot declare incidents, change severity levels, post notes, upload files, or view admin logs.

---

## 🛠️ Technology Stack
- **Backend:** Python 3, Flask, Flask-SQLAlchemy (ORM), bcrypt (Password hashing), geoip2 (IP geolocation).
- **PDF Engine:** ReportLab (Native vector drawing & document flow).
- **Database:** SQLite.
- **Frontend:** HTML5, Vanilla CSS3 (Custom Cyber Dark theme, CSS variables, glassmorphism design), Bootstrap 5, marked.js (Markdown parser).

---

## ⚙️ Installation & Setup

### 1. Prerequisites
Ensure you have Python 3.8+ installed on your system.

### 2. Install Dependencies
Navigate to the root directory and install requirements:
```bash
pip install -r requirements.txt
```

### 3. Initialize & Seed Database
Re-seed the database to create SQLite tables and load default settings, threat feeds, and mock accounts:
```bash
python seed.py
```

### 4. Start Server
Run the Flask development server:
```bash
python run.py
```
Open your browser and navigate to `http://127.0.0.1:5000` to access the platform interface.

---

## 🔐 Default Credentials for Testing

| Account Role | Username | Password | Access Level |
| :--- | :--- | :--- | :--- |
| **Super Admin** | `admin` | `SentinelXDR2026!` | Full admin read/write |
| **SOC Analyst** | `analyst` | `analyst123!` | Analyst read/write |
| **Viewer** | `viewer` | `viewer123!` | Read-only |

---

## 🧪 Running Automated Tests
The platform features automated tests for log parser syntax rules and threat intelligence triggers. Run tests using:
```bash
python -m unittest test_threat_detection.py test_parser.py
```
