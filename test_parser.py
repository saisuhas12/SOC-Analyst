import unittest
import datetime
from app.services.geoip_service import GeoIPService
from app.services.parser_service import LogParserService

class TestLogParserAndGeoIP(unittest.TestCase):
    def setUp(self):
        self.geoip_service = GeoIPService()
        self.parser_service = LogParserService(self.geoip_service)

    def tearDown(self):
        self.geoip_service.close()

    def test_geoip_private_ranges(self):
        """Ensure private IP ranges resolve to internal/local labels."""
        c1, city1 = self.geoip_service.resolve("192.168.1.50")
        c2, city2 = self.geoip_service.resolve("10.0.0.1")
        c3, city3 = self.geoip_service.resolve("127.0.0.1")
        
        self.assertEqual(c1, "Internal Network")
        self.assertEqual(c2, "Internal Network")
        self.assertEqual(c3, "Local Loopback")

    def test_geoip_public_fallback(self):
        """Ensure public IPs resolve to deterministic locations offline."""
        # 45.x.x.x should resolve to Russia/Moscow in our mock mapper
        country, city = self.geoip_service.resolve("45.10.10.1")
        self.assertEqual(country, "Russia")
        self.assertEqual(city, "Moscow")

        # 14.x.x.x should resolve to North Korea/Pyongyang
        country, city = self.geoip_service.resolve("14.0.0.1")
        self.assertEqual(country, "North Korea")
        self.assertEqual(city, "Pyongyang")

    def test_parse_ssh_success(self):
        """Ensure successful SSH logins are correctly parsed and mapped."""
        log_line = "Jun 18 01:11:16 auth sshd[1234]: Accepted password for analyst from 192.168.1.100 port 43210 ssh2"
        events = self.parser_service.parse_file("test.log", log_line.encode('utf-8'))
        
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event['event_type'], 'LOGIN_SUCCESS')
        self.assertEqual(event['status'], 'Success')
        self.assertEqual(event['username'], 'analyst')
        self.assertEqual(event['source_ip'], '192.168.1.100')
        self.assertEqual(event['severity'], 'Low')
        self.assertEqual(event['mitre_technique'], 'T1078 - Valid Accounts')
        self.assertEqual(event['mitre_tactic'], 'Defense Evasion / Persistence / Initial Access / Privilege Escalation')

    def test_parser_severity_escalation(self):
        """Ensure failed logins escalate severity based on cumulative count per IP."""
        # 12 failed attempts from the same IP
        failed_lines = []
        ip = "185.20.20.10"
        for i in range(12):
            failed_lines.append(f"Jun 18 02:10:00 auth sshd[222]: Failed password for root from {ip} port 50000 ssh2")
            
        content = "\n".join(failed_lines)
        events = self.parser_service.parse_file("bruteforce.log", content.encode('utf-8'))
        
        self.assertEqual(len(events), 12)
        
        # 1st failure = Low (index 0)
        self.assertEqual(events[0]['severity'], 'Low')
        self.assertEqual(events[0]['mitre_technique'], 'T1110 - Brute Force')

        # 4th failure = Medium (index 3)
        self.assertEqual(events[3]['severity'], 'Medium')
        self.assertEqual(events[3]['mitre_technique'], 'T1110.001 - Brute Force: Password Guessing')

        # 7th failure = High (index 6)
        self.assertEqual(events[6]['severity'], 'High')
        
        # 11th failure = Critical (index 10)
        self.assertEqual(events[10]['severity'], 'Critical')

    def test_parse_csv(self):
        """Ensure CSV formatting matches expected schema parsing."""
        csv_content = (
            "timestamp,username,source_ip,event_type,status,message\n"
            "2026-06-18 10:00:00,admin,45.1.1.1,LOGIN_FAILED,Failure,Bad password attempt\n"
            "2026-06-18 10:01:00,admin,192.168.1.5,LOGIN_SUCCESS,Success,Valid login\n"
        )
        events = self.parser_service.parse_file("test.csv", csv_content.encode('utf-8'))
        
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]['event_type'], 'LOGIN_FAILED')
        self.assertEqual(events[0]['country'], 'Russia') # resolved from 45.1.1.1
        self.assertEqual(events[1]['event_type'], 'LOGIN_SUCCESS')
        self.assertEqual(events[1]['country'], 'Internal Network')

if __name__ == '__main__':
    unittest.main()
