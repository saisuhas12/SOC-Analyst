import datetime
from app import create_app, db
from app.models.user import User
from app.models.uploaded_log import UploadedLog
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.models.ioc import IOCIndicator, IOCMatch
from app.models.setting import SystemSetting
from app.services.geoip_service import GeoIPService

def seed_database():
    app = create_app()
    with app.app_context():
        print("Recreating database tables...")
        db.drop_all()
        db.create_all()
        
        print("Provisioning system settings...")
        SystemSetting.set_value('brute_force_threshold', '5')
        
        print("Provisioning default accounts...")
        # 1. Default Admin Account
        admin = User(
            username='admin',
            email='admin@sentinelxdr.com',
            role='admin'
        )
        admin.set_password('SentinelXDR2026!')
        db.session.add(admin)
        
        # 2. Default Analyst Account
        analyst = User(
            username='analyst',
            email='analyst@sentinelxdr.com',
            role='analyst'
        )
        analyst.set_password('analyst123!')
        db.session.add(analyst)
        db.session.flush() # get analyst.id and admin.id
        
        print("Provisioning mock threat intelligence indicators (IOCs)...")
        # 1. IP Indicator
        ioc_ip = IOCIndicator(
            ioc_type='IP Address',
            value='45.89.230.1',
            severity='Critical',
            description='Known threat actor SSH brute-force host targeting Linux endpoints',
            created_by_id=analyst.id
        )
        db.session.add(ioc_ip)
        
        # 2. Domain Indicator
        ioc_domain = IOCIndicator(
            ioc_type='Domain',
            value='phishing-malware-c2.com',
            severity='Critical',
            description='Active C2 beaconing server domain linked to recent campaign',
            created_by_id=analyst.id
        )
        db.session.add(ioc_domain)
        
        # 3. File Hash Indicator
        ioc_hash = IOCIndicator(
            ioc_type='File Hash',
            value='5d41402abc4b2a76b9719d911017c592',
            severity='High',
            description='Emotet loader payload signature detected in phishing attachment',
            created_by_id=analyst.id
        )
        db.session.add(ioc_hash)
        db.session.flush()
        
        print("Ingesting initial mock log data for dashboard visualization...")
        # Add a mock log file upload history
        uploaded_log = UploadedLog(
            filename='syslog_threat_feed_demo.log',
            file_size=12400,
            log_count=35,
            user_id=analyst.id,
            upload_time=datetime.datetime.utcnow() - datetime.timedelta(hours=6)
        )
        db.session.add(uploaded_log)
        db.session.flush() # get uploaded_log.id
        
        # Create GeoIP and seed realistic security events over the past 7 days
        geoip = GeoIPService()
        
        # Helper to generate events
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

        # Seed data over last 6 days to populate graphs
        # Day 5 (5 days ago)
        add_event(5, 8, '192.168.10.15', 'sysadmin', 'LOGIN_SUCCESS', 'Success', 
                  'Session opened for user sysadmin from 192.168.10.15', 'Low', 'T1078 - Valid Accounts', 'Defense Evasion')
        
        # Day 4: Ingest events matching our Critical IOC IP and trigger alert
        ev_ioc = add_event(4, 14, '45.89.230.1', 'root', 'LOGIN_FAILED', 'Failure', 
                  'Failed password for root from 45.89.230.1 port 52134 ssh2. Context: Host is matching threat intelligence database.', 'Critical', 'T1110 - Brute Force', 'Credential Access')
        
        # Create IOC match and alert for Day 4
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

        # Day 3: Ingest a simulated phishing event with a C2 domain in it
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

        # Day 2: Ingest brute force from IP 82.20.10.5 (exceeds threshold 5)
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
                
        # Create Brute Force alert
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

        # Day 1: Credential spraying detection from IP 220.180.50.2 (targeting test, oracle, admin)
        spray_ip = '220.180.50.2'
        spray_ts_list = []
        for username in ['test', 'oracle', 'admin']:
            ev_spray = add_event(1, 15, spray_ip, username, 'LOGIN_FAILED', 'Failure', 
                      f'Failed password for {username} from {spray_ip}', 'Medium', 'T1110 - Brute Force', 'Credential Access')
            spray_ts_list.append(ev_spray.timestamp)
            
        alert_spray = Alert(
            alert_type='Suspicious Login Pattern',
            severity='High',
            priority='P2',
            status='New',
            source_ip=spray_ip,
            attempt_count=3,
            first_seen=min(spray_ts_list),
            last_seen=max(spray_ts_list),
            description=f"Suspicious Login Pattern: Credential spraying detected from IP {spray_ip} targeting 3 distinct usernames (test, oracle, admin).",
            mitre_technique="T1110.003 - Brute Force: Credential Spraying",
            mitre_tactic="Credential Access",
            created_at=max(spray_ts_list)
        )
        db.session.add(alert_spray)

        # Day 0: Russian IP brute force (11 failures -> Critical Brute Force Alert)
        russian_ip = '185.100.20.5'
        ru_ts_list = []
        for i in range(11):
            ev_ru = add_event(0, 4, russian_ip, 'ftpuser', 'LOGIN_FAILED', 'Failure', 
                      f"Failed password for invalid user ftpuser from {russian_ip} port {50000+i} ssh2", 'Critical', 'T1110 - Brute Force', 'Credential Access')
            ru_ts_list.append(ev_ru.timestamp)
            
        alert_bf_ru = Alert(
            alert_type='Brute Force',
            severity='Critical',
            priority='P1',
            status='New',
            source_ip=russian_ip,
            attempt_count=11,
            first_seen=min(ru_ts_list),
            last_seen=max(ru_ts_list),
            description=f"Brute force detection: 11 failed login attempts from IP {russian_ip}.",
            mitre_technique="T1110.001 - Brute Force: Password Guessing",
            mitre_tactic="Credential Access",
            created_at=max(ru_ts_list)
        )
        db.session.add(alert_bf_ru)
        
        # Day 0: Suspicious login pattern (Success after failures from IP 192.168.1.200)
        pattern_ip = '192.168.1.200'
        pat_ts_list = []
        for i in range(4):
            ev_pat_fail = add_event(0, 10, pattern_ip, 'administrator', 'LOGIN_FAILED', 'Failure',
                        f"Failed login attempt for administrator from IP {pattern_ip} (Attempt {i+1})", 'Medium', 'T1110 - Brute Force', 'Credential Access')
            pat_ts_list.append(ev_pat_fail.timestamp)
            
        # Successful login following failures
        ev_pat_success = add_event(0, 10, pattern_ip, 'administrator', 'LOGIN_SUCCESS', 'Success',
                    f"Session opened for user administrator from IP {pattern_ip}", 'Critical', 'T1078 - Valid Accounts', 'Defense Evasion')
        pat_ts_list.append(ev_pat_success.timestamp)
        
        alert_pat = Alert(
            alert_type='Suspicious Login Pattern',
            severity='Critical',
            priority='P1',
            status='New',
            source_ip=pattern_ip,
            attempt_count=5,
            first_seen=min(pat_ts_list),
            last_seen=ev_pat_success.timestamp,
            description=f"Suspicious Login Pattern: Successful login for user 'administrator' from IP {pattern_ip} following 4 authentication failures. Potential compromise!",
            mitre_technique="T1110 - Brute Force",
            mitre_tactic="Credential Access / Initial Access",
            created_at=ev_pat_success.timestamp
        )
        db.session.add(alert_pat)

        db.session.commit()
        geoip.close()
        print("Database successfully seeded.")
        print("-" * 50)
        print("Credentials:")
        print("1. Admin Account:  admin    / SentinelXDR2026!")
        print("2. Analyst Account: analyst  / analyst123!")
        print("-" * 50)

if __name__ == '__main__':
    seed_database()
