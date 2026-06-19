import unittest
import datetime
from config import Config
from app import create_app, db
from app.models.user import User
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.models.ioc import IOCIndicator, IOCMatch
from app.models.setting import SystemSetting
from app.models.uploaded_log import UploadedLog
from app.services.detection_service import DetectionService

class TestingConfig(Config):
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    TESTING = True

class TestThreatDetection(unittest.TestCase):
    def setUp(self):
        # Configure app for testing in memory SQLite
        self.app = create_app(TestingConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()

        
        # Provision default analyst
        self.analyst = User(username='test_analyst', email='test_analyst@test.com')
        self.analyst.set_password('test_pass123!')
        db.session.add(self.analyst)
        
        # Provision default settings
        SystemSetting.set_value('brute_force_threshold', '3')
        
        # Uploaded Log entry
        self.log_file = UploadedLog(
            filename='test_ingest.log',
            file_size=1024,
            log_count=0,
            user_id=1 # placeholder
        )
        db.session.add(self.log_file)
        
        db.session.commit()
        
        # Re-fetch or assign uploader id
        self.log_file.user_id = self.analyst.id
        db.session.commit()
        
        self.detector = DetectionService()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_brute_force_detection_below_threshold(self):
        """Ensure failures below threshold do not trigger brute force alerts."""
        ip = "192.168.1.10"
        
        # Create 2 failures (threshold is 3)
        events = []
        for i in range(2):
            se = SecurityEvent(
                uploaded_log_id=self.log_file.id,
                timestamp=datetime.datetime.utcnow(),
                event_type='LOGIN_FAILED',
                status='Failure',
                source_ip=ip,
                username='admin',
                message='Failed login attempt',
                severity='Low'
            )
            db.session.add(se)
            events.append(se)
            
        self.detector.process_events(events)
        db.session.commit()
        
        # Query alerts
        alert = Alert.query.filter_by(source_ip=ip, alert_type='Brute Force').first()
        self.assertIsNone(alert)

    def test_brute_force_detection_and_escalation(self):
        """Ensure failed logins trigger alerts and escalate severity dynamically."""
        ip = "192.168.1.20"
        
        # Create 3 failures (reaches threshold)
        events1 = []
        for i in range(3):
            se = SecurityEvent(
                uploaded_log_id=self.log_file.id,
                timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=10 - i),
                event_type='LOGIN_FAILED',
                status='Failure',
                source_ip=ip,
                username='admin',
                message='Failed login attempt',
                severity='Low'
            )
            db.session.add(se)
            events1.append(se)
            
        self.detector.process_events(events1)
        db.session.commit()
        
        # Check alert was created
        alert = Alert.query.filter_by(source_ip=ip, alert_type='Brute Force').first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.attempt_count, 3)
        self.assertEqual(alert.severity, 'Medium')
        self.assertEqual(alert.priority, 'P3')
        self.assertEqual(alert.status, 'New')
        
        # Add 3 more failures (reaches threshold * 2 = 6, triggers High severity)
        events2 = []
        for i in range(3):
            se = SecurityEvent(
                uploaded_log_id=self.log_file.id,
                timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=5 - i),
                event_type='LOGIN_FAILED',
                status='Failure',
                source_ip=ip,
                username='admin',
                message='Failed login attempt',
                severity='Low'
            )
            db.session.add(se)
            events2.append(se)
            
        self.detector.process_events(events2)
        db.session.commit()
        
        # Check alert is updated and escalated
        alert = Alert.query.filter_by(source_ip=ip, alert_type='Brute Force').first()
        self.assertEqual(alert.attempt_count, 6)
        self.assertEqual(alert.severity, 'High')
        self.assertEqual(alert.priority, 'P2')

    def test_suspicious_login_pattern_success_after_failure(self):
        """Ensure successful login following failed login triggers suspicious login pattern alert."""
        ip = "192.168.1.30"
        
        # 3 failures followed by success
        events = []
        base_time = datetime.datetime.utcnow()
        for i in range(3):
            se = SecurityEvent(
                uploaded_log_id=self.log_file.id,
                timestamp=base_time - datetime.timedelta(minutes=10 - i),
                event_type='LOGIN_FAILED',
                status='Failure',
                source_ip=ip,
                username='victim_user',
                message='Failed login attempt',
                severity='Low'
            )
            db.session.add(se)
            events.append(se)
            
        success_event = SecurityEvent(
            uploaded_log_id=self.log_file.id,
            timestamp=base_time,
            event_type='LOGIN_SUCCESS',
            status='Success',
            source_ip=ip,
            username='victim_user',
            message='Session opened for user victim_user',
            severity='Low'
        )
        db.session.add(success_event)
        events.append(success_event)
        
        self.detector.process_events(events)
        db.session.commit()
        
        # Assert alert
        alert = Alert.query.filter_by(source_ip=ip, alert_type='Suspicious Login Pattern').first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, 'Critical')
        self.assertEqual(alert.priority, 'P1')
        self.assertIn("compromise", alert.description)

    def test_credential_spraying_detection(self):
        """Ensure targeting multiple distinct accounts from one IP triggers suspicious login pattern."""
        ip = "192.168.1.40"
        
        # Target 3 distinct users
        events = []
        for u in ['user_a', 'user_b', 'user_c']:
            se = SecurityEvent(
                uploaded_log_id=self.log_file.id,
                timestamp=datetime.datetime.utcnow(),
                event_type='LOGIN_FAILED',
                status='Failure',
                source_ip=ip,
                username=u,
                message=f'Failed password for user {u}',
                severity='Low'
            )
            db.session.add(se)
            events.append(se)
            
        self.detector.process_events(events)
        db.session.commit()
        
        # Assert spraying alert
        alert = Alert.query.filter(
            Alert.source_ip == ip,
            Alert.alert_type == 'Suspicious Login Pattern',
            Alert.description.like('%spraying%')
        ).first()
        
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, 'High')
        self.assertEqual(alert.priority, 'P2')

    def test_ioc_matching_engine(self):
        """Ensure log matching against threat intelligence indicators registers matches and alerts."""
        # Add indicator
        ioc = IOCIndicator(
            ioc_type='Domain',
            value='phishing-dns.com',
            severity='High',
            description='Known phishing DNS',
            created_by_id=self.analyst.id
        )
        db.session.add(ioc)
        db.session.commit()
        
        # Parse a log event matching indicator
        se = SecurityEvent(
            uploaded_log_id=self.log_file.id,
            timestamp=datetime.datetime.utcnow(),
            event_type='SYS_WARN',
            status='Unknown',
            source_ip='192.168.1.50',
            username='unknown',
            message='DNS Query for domain phishing-dns.com resolved to C2',
            severity='Medium'
        )
        db.session.add(se)
        
        self.detector.process_events([se])
        db.session.commit()
        
        # Check IOC match is stored
        match = IOCMatch.query.filter_by(matched_value='phishing-dns.com').first()
        self.assertIsNotNone(match)
        self.assertEqual(match.security_event_id, se.id)
        
        # Check IOC Alert is generated
        alert = Alert.query.filter_by(ioc_indicator_id=ioc.id, alert_type='IOC Match').first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, 'High')
        self.assertEqual(alert.priority, 'P2')
        self.assertEqual(alert.mitre_technique, 'T1566 - Phishing')

if __name__ == '__main__':
    unittest.main()
