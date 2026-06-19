import datetime
from app import create_app, db
from app.models.user import User
from app.models.uploaded_log import UploadedLog
from app.models.security_event import SecurityEvent
from app.services.geoip_service import GeoIPService

def seed_database():
    app = create_app()
    with app.app_context():
        print("Recreating database tables...")
        db.drop_all()
        db.create_all()
        
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
        db.session.flush() # get analyst.id
        
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

        # Seed data over last 6 days to populate graphs
        # Day 5 (5 days ago)
        add_event(5, 8, '192.168.10.15', 'sysadmin', 'LOGIN_SUCCESS', 'Success', 
                  'Session opened for user sysadmin from 192.168.10.15', 'Low', 'T1078 - Valid Accounts', 'Defense Evasion')
        add_event(5, 14, '45.89.230.1', 'root', 'LOGIN_FAILED', 'Failure', 
                  'Failed password for root from 45.89.230.1 port 52134 ssh2', 'Low', 'T1110 - Brute Force', 'Credential Access')
        
        # Day 4
        add_event(4, 9, '192.168.10.15', 'sysadmin', 'LOGIN_SUCCESS', 'Success', 
                  'Session opened for user sysadmin from 192.168.10.15', 'Low', 'T1078 - Valid Accounts', 'Defense Evasion')
        add_event(4, 22, '45.89.230.1', 'admin', 'LOGIN_FAILED', 'Failure', 
                  'Failed password for invalid user admin from 45.89.230.1 port 54312 ssh2', 'Low', 'T1110 - Brute Force', 'Credential Access')
        add_event(4, 22, '45.89.230.1', 'admin', 'LOGIN_FAILED', 'Failure', 
                  'Failed password for invalid user admin from 45.89.230.1 port 54314 ssh2', 'Low', 'T1110 - Brute Force', 'Credential Access')
        add_event(4, 22, '45.89.230.1', 'admin', 'LOGIN_FAILED', 'Failure', 
                  'Failed password for invalid user admin from 45.89.230.1 port 54316 ssh2', 'Medium', 'T1110.001 - Brute Force: Password Guessing', 'Credential Access')

        # Day 3
        add_event(3, 10, '192.168.1.50', 'analyst', 'LOGIN_SUCCESS', 'Success', 
                  'Session opened for user analyst', 'Low', 'T1078 - Valid Accounts', 'Defense Evasion')
        for i in range(5): # 5 failures from North Korea IP
            sev = 'Medium' if i >= 2 else 'Low'
            tech = 'T1110.001 - Brute Force: Password Guessing' if i >= 2 else 'T1110 - Brute Force'
            add_event(3, 12, '14.10.1.5', 'guest', 'LOGIN_FAILED', 'Failure', 
                      f'Failed login attempt for guest from IP 14.10.1.5 (Attempt {i+1})', sev, tech, 'Credential Access')
                      
        # Day 2
        add_event(2, 6, '192.168.1.50', 'analyst', 'LOGIN_SUCCESS', 'Success', 
                  'Session opened for user analyst', 'Low', 'T1078 - Valid Accounts', 'Defense Evasion')
        add_event(2, 19, '82.20.10.5', 'root', 'LOGIN_FAILED', 'Failure', 
                  'Failed password for root from 82.20.10.5 port 60124 ssh2', 'Low', 'T1110 - Brute Force', 'Credential Access')
        add_event(2, 20, '82.20.10.5', 'root', 'LOGIN_FAILED', 'Failure', 
                  'Failed password for root from 82.20.10.5 port 60126 ssh2', 'Low', 'T1110 - Brute Force', 'Credential Access')

        # Day 1 (Yesterday)
        add_event(1, 8, '192.168.10.15', 'sysadmin', 'LOGIN_SUCCESS', 'Success', 
                  'Session opened for user sysadmin', 'Low', 'T1078 - Valid Accounts', 'Defense Evasion')
        add_event(1, 15, '220.180.50.2', 'test', 'LOGIN_FAILED', 'Failure', 
                  'Failed password for test from 220.180.50.2', 'Low', 'T1110 - Brute Force', 'Credential Access')
        add_event(1, 15, '220.180.50.2', 'oracle', 'LOGIN_FAILED', 'Failure', 
                  'Failed password for oracle from 220.180.50.2', 'Low', 'T1110 - Brute Force', 'Credential Access')
        add_event(1, 15, '220.180.50.2', 'admin', 'LOGIN_FAILED', 'Failure', 
                  'Failed password for admin from 220.180.50.2', 'Medium', 'T1110.001 - Brute Force: Password Guessing', 'Credential Access')

        # Day 0 (Today)
        add_event(0, 1, '192.168.1.50', 'admin', 'LOGIN_SUCCESS', 'Success', 
                  'Session opened for user admin', 'Low', 'T1078 - Valid Accounts', 'Defense Evasion')
        
        # High volume brute force from Russian IP today (11 failures -> escalates to Critical)
        russian_ip = '185.100.20.5'
        for i in range(11):
            if i < 2:
                sev = 'Low'
                tech = 'T1110 - Brute Force'
            elif i < 5:
                sev = 'Medium'
                tech = 'T1110.001 - Brute Force: Password Guessing'
            elif i < 10:
                sev = 'High'
                tech = 'T1110.001 - Brute Force: Password Guessing'
            else:
                sev = 'Critical'
                tech = 'T1110.001 - Brute Force: Password Guessing'
                
            msg = f"Failed password for invalid user ftpuser from {russian_ip} port {50000+i} ssh2"
            add_event(0, 4, russian_ip, 'ftpuser', 'LOGIN_FAILED', 'Failure', 
                      msg, sev, tech, 'Credential Access')

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
