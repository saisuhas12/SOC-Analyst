import datetime
import os
from app import create_app, db
from app.models.user import User
from app.models.setting import SystemSetting
from app.models.uploaded_log import UploadedLog
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.models.ioc import IOCIndicator, IOCMatch
from app.models.incident import Incident
from app.models.incident_note import IncidentNote
from app.models.audit_log import AuditLog
from app.models.report import Report
from app.services.pdf_generator import PDFReportGenerator
from app.services.geoip_service import GeoIPService
from flask_migrate import stamp

def initialize_database():
    app = create_app()
    with app.app_context():
        print("Ensuring database tables exist...")
        db.create_all()
        
        # Stamp the migration database to the head (latest) state
        try:
            stamp()
            print("Database migration index stamped successfully.")
        except Exception as e:
            print(f"Database migration stamp skipped/failed (normal if migrations not initialised): {e}")

        # Check if the database has already been seeded
        admin_user = User.query.filter_by(username='admin').first()
        if admin_user:
            print("Admin account detected. Database is already seeded.")
            return

        print("No default accounts found. Commencing production database seeding...")
        
        # Provision default settings
        SystemSetting.set_value('brute_force_threshold', '5')
        
        # 1. Default Admin Account (Super Admin)
        admin = User(
            username='admin',
            email='admin@sentinelxdr.com',
            role='admin'
        )
        admin.set_password('SentinelXDR2026!')
        db.session.add(admin)
        
        # 2. Default Analyst Account (SOC Analyst)
        analyst = User(
            username='analyst',
            email='analyst@sentinelxdr.com',
            role='analyst'
        )
        analyst.set_password('analyst123!')
        db.session.add(analyst)
        
        # 3. Default Viewer Account (Viewer)
        viewer = User(
            username='viewer',
            email='viewer@sentinelxdr.com',
            role='viewer'
        )
        viewer.set_password('viewer123!')
        db.session.add(viewer)
        db.session.flush() # Extract IDs
        
        print("Provisioning mock threat intelligence indicators (IOCs)...")
        ioc_ip = IOCIndicator(
            ioc_type='IP Address',
            value='45.89.230.1',
            severity='Critical',
            description='Known threat actor SSH brute-force host targeting Linux endpoints',
            created_by_id=analyst.id
        )
        db.session.add(ioc_ip)
        
        ioc_domain = IOCIndicator(
            ioc_type='Domain',
            value='phishing-malware-c2.com',
            severity='Critical',
            description='Active C2 beaconing server domain linked to recent campaign',
            created_by_id=analyst.id
        )
        db.session.add(ioc_domain)
        
        ioc_hash = IOCIndicator(
            ioc_type='File Hash',
            value='5d41402abc4b2a76b9719d911017c592',
            severity='High',
            description='Emotet loader payload signature detected in phishing attachment',
            created_by_id=analyst.id
        )
        db.session.add(ioc_hash)
        db.session.flush()
        
        print("Ingesting initial logs for dashboard metrics...")
        uploaded_log = UploadedLog(
            filename='syslog_threat_feed_demo.log',
            file_size=12400,
            log_count=35,
            user_id=analyst.id,
            upload_time=datetime.datetime.utcnow() - datetime.timedelta(hours=6)
        )
        db.session.add(uploaded_log)
        db.session.flush()
        
        # Build GeoIP and mock events
        db_path = app.config.get('GEOLITE2_DB_PATH')
        geoip = GeoIPService(db_path)
        
        def add_event(days_ago, hour, ip, username, event_type, status, message, severity, mitre_t, mitre_tac):
            country, city = geoip.resolve(ip)
            ts = datetime.datetime.utcnow() - datetime.timedelta(days=days_ago)
            ts = ts.replace(hour=hour, minute=15, second=30)
            
            se = SecurityEvent(
                uploaded_log_id=uploaded_log.id,
                timestamp=ts,
                event_type=event_type,
                status=status,
                source_ip=ip,
                username=username,
                message=message,
                severity=severity,
                mitre_technique=mitre_t,
                mitre_tactic=mitre_tac,
                country=country,
                city=city
            )
            db.session.add(se)
            return se

        # Seed initial timeline events over last 5 days
        add_event(5, 8, '192.168.10.15', 'sysadmin', 'LOGIN_SUCCESS', 'Success', 
                  'Session opened for user sysadmin from 192.168.10.15', 'Low', 'T1078 - Valid Accounts', 'Defense Evasion')
        
        ev_ioc = add_event(4, 14, '45.89.230.1', 'root', 'LOGIN_FAILED', 'Failure', 
                  'Failed password for root from 45.89.230.1 port 52134 ssh2. Context: Host is matching threat intelligence database.', 'Critical', 'T1110 - Brute Force', 'Credential Access')
        
        ioc_match_ip = IOCMatch(
            ioc_indicator_id=ioc_ip.id,
            security_event_id=ev_ioc.id,
            matched_value='45.89.230.1',
            matched_at=ev_ioc.timestamp,
            details=f"Threat IP resolved during parsing: {ev_ioc.message}"
        )
        db.session.add(ioc_match_ip)
        
        alert_ioc = Alert(
            alert_type='IOC Match',
            severity='Critical',
            priority='P1',
            status='New',
            source_ip='45.89.230.1',
            attempt_count=1,
            first_seen=ev_ioc.timestamp,
            last_seen=ev_ioc.timestamp,
            ioc_indicator_id=ioc_ip.id,
            description="IOC Match: matched threat indicator '45.89.230.1' (IP Address) on IP 45.89.230.1.",
            mitre_technique="T1071 - Standard Application Layer Protocol",
            mitre_tactic="Command and Control",
            created_at=ev_ioc.timestamp
        )
        db.session.add(alert_ioc)

        ev_c2 = add_event(3, 10, '192.168.1.50', 'analyst', 'SYS_ALERT', 'Success', 
                  'DNS Query resolved: phishing-malware-c2.com to 104.244.42.1. Agent triggered alert.', 'High', 'T1566 - Phishing', 'Initial Access')
        
        ioc_match_c2 = IOCMatch(
            ioc_indicator_id=ioc_domain.id,
            security_event_id=ev_c2.id,
            matched_value='phishing-malware-c2.com',
            matched_at=ev_c2.timestamp,
            details=f"C2 Domain resolved in message: {ev_c2.message}"
        )
        db.session.add(ioc_match_c2)
        
        alert_c2 = Alert(
            alert_type='IOC Match',
            severity='Critical',
            priority='P1',
            status='New',
            source_ip='192.168.1.50',
            attempt_count=1,
            first_seen=ev_c2.timestamp,
            last_seen=ev_c2.timestamp,
            ioc_indicator_id=ioc_domain.id,
            description="IOC Match: matched threat indicator 'phishing-malware-c2.com' (Domain) on IP 192.168.1.50.",
            mitre_technique="T1566 - Phishing",
            mitre_tactic="Initial Access",
            created_at=ev_c2.timestamp
        )
        db.session.add(alert_c2)

        failed_ip_2 = '82.20.10.5'
        first_ts_2 = None
        last_ts_2 = None
        for i in range(6):
            ev_bf = add_event(2, 19, failed_ip_2, 'root', 'LOGIN_FAILED', 'Failure', 
                      f'Failed password for root from {failed_ip_2} port {60000+i} ssh2', 'Medium', 'T1110 - Brute Force', 'Credential Access')
            if i == 0:
                first_ts_2 = ev_bf.timestamp
            if i == 5:
                last_ts_2 = ev_bf.timestamp
                
        alert_bf_2 = Alert(
            alert_type='Brute Force',
            severity='Medium',
            priority='P3',
            status='New',
            source_ip=failed_ip_2,
            attempt_count=6,
            first_seen=first_ts_2,
            last_seen=last_ts_2,
            description=f"Brute force detection: 6 failed login attempts from IP {failed_ip_2}.",
            mitre_technique="T1110.001 - Brute Force: Password Guessing",
            mitre_tactic="Credential Access",
            created_at=last_ts_2
        )
        db.session.add(alert_bf_2)
        db.session.flush()

        # Seed Incidents
        inc1 = Incident(
            title="Incident #1: Suspicious Login Pattern Containment",
            description="Escalated investigation into authentication failures and brute force login activity.",
            severity="High",
            status="Investigating",
            assigned_to_id=analyst.id,
            alert_id=alert_bf_2.id,
            created_at=alert_bf_2.created_at
        )
        inc1.add_timeline_event("Incident declared.", "System")
        inc1.add_timeline_event("Assigned to analyst.", "admin")
        db.session.add(inc1)
        db.session.flush()

        # Seed Notes
        note1 = IncidentNote(
            incident_id=inc1.id,
            user_id=analyst.id,
            note_text="## Case Containment Analysis\n\n- Commenced firewall rules adjustments targeting IP range `82.20.10.0/24`.\n- Instructed sysadmin to audit logon status parameter values.",
            created_at=inc1.created_at + datetime.timedelta(minutes=30)
        )
        db.session.add(note1)

        # Seed Audit Logs
        log1 = AuditLog(
            username="admin",
            action_type="User Action",
            details="Provisioned user 'analyst' with role 'analyst'",
            ip_address="127.0.0.1",
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(days=2)
        )
        db.session.add(log1)

        # Seed Reports
        rep = Report(
            report_type="Daily SOC Report",
            title="Seeded Production Status Report",
            created_by_id=admin.id,
            executive_summary="Production deployment check. Initial threat status remains stable.",
            findings="No active network compromises detected.",
            recommendations="Ensure system alerts thresholds are monitored weekly.",
            charts_data={'severity': {'labels': ['Low', 'Medium', 'High', 'Critical'], 'counts': [0, 1, 0, 2]}},
            pdf_path="uploads/reports/seed_soc_report.pdf",
            created_at=datetime.datetime.utcnow() - datetime.timedelta(hours=1)
        )
        db.session.add(rep)
        db.session.flush()

        # Generate seeded report PDF on persistent mount
        reports_dir = os.path.join(app.static_folder, 'uploads', 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        pdf_file_path = os.path.join(reports_dir, "seed_soc_report.pdf")
        try:
            PDFReportGenerator.generate(rep, pdf_file_path)
            print("Successfully generated seeded report PDF.")
        except Exception as e:
            print(f"Warning: Failed to compile seeded report PDF: {e}")

        db.session.commit()
        geoip.close()
        print("Production database initialized and seeded successfully.")

if __name__ == '__main__':
    initialize_database()
