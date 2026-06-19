import re
import csv
import datetime
from io import StringIO
from app.services.geoip_service import GeoIPService

class LogParserService:
    def __init__(self, geoip_service: GeoIPService):
        self.geoip_service = geoip_service

        # Regex compiled patterns for text log analysis
        self.ssh_failed_pattern = re.compile(
            r'Failed password for (?:invalid user )?(\S+) from (\S+) port \d+ ssh2', 
            re.IGNORECASE
        )
        self.ssh_success_pattern = re.compile(
            r'Accepted password for (\S+) from (\S+) port \d+ ssh2', 
            re.IGNORECASE
        )
        
        # Generic auth patterns
        self.generic_fail_pattern = re.compile(
            r'(?:login failed|authentication failure|failed login|auth failed|invalid credentials)(?: for user (\S+))?(?: from (\S+))?', 
            re.IGNORECASE
        )
        self.generic_success_pattern = re.compile(
            r'(?:login success|session opened|successful login|auth success)(?: for user (\S+))?(?: from (\S+))?', 
            re.IGNORECASE
        )
        
        # IP Extraction pattern
        self.ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')

    def parse_file(self, filename, content_bytes):
        """
        Parses a log file (CSV, TXT, or LOG) and returns a list of dictionaries 
        ready to be saved as SecurityEvent models.
        """
        text_content = content_bytes.decode('utf-8', errors='ignore')
        events = []
        
        # Track failed logins per IP within this file to compute dynamic severity
        # IP -> count
        failed_attempts_by_ip = {}

        if filename.endswith('.csv'):
            events = self._parse_csv(text_content, failed_attempts_by_ip)
        else:
            events = self._parse_text(text_content, failed_attempts_by_ip)
            
        return events

    def _determine_severity(self, failure_count):
        """
        Dynamic severity scaling rules:
        1-2 failures = Low
        3-5 failures = Medium
        6-10 failures = High
        10+ failures = Critical
        """
        if failure_count <= 2:
            return "Low"
        elif failure_count <= 5:
            return "Medium"
        elif failure_count <= 10:
            return "High"
        else:
            return "Critical"

    def _parse_timestamp(self, ts_str):
        if not ts_str:
            return datetime.datetime.utcnow()
        
        # Try various formats
        formats = [
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%b %d %H:%M:%S', # Syslog style (no year) e.g., Jun 18 01:11:16
        ]
        
        for fmt in formats:
            try:
                dt = datetime.datetime.strptime(ts_str.strip(), fmt)
                if fmt == '%b %d %H:%M:%S':
                    # Syslog has no year, assume current year
                    dt = dt.replace(year=datetime.datetime.utcnow().year)
                return dt
            except ValueError:
                continue
                
        # Extract date-like pattern if possible
        try:
            # Simple regex search for 2026-06-18 01:11:16 style
            match = re.search(r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}', ts_str)
            if match:
                dt_str = match.group(0).replace('T', ' ')
                return datetime.datetime.strptime(dt_str, '%Y-%m-%d %H:%M:%S')
        except Exception:
            pass

        return datetime.datetime.utcnow()

    def _parse_csv(self, content, failed_attempts):
        events = []
        f = StringIO(content)
        reader = csv.DictReader(f)
        
        for row in reader:
            # Read CSV columns with fallbacks
            ts_val = row.get('timestamp') or row.get('time') or row.get('Timestamp')
            timestamp = self._parse_timestamp(ts_val)
            
            username = row.get('username') or row.get('user') or row.get('Username') or 'unknown'
            source_ip = row.get('source_ip') or row.get('src_ip') or row.get('ip') or row.get('Source IP') or '0.0.0.0'
            event_type = row.get('event_type') or row.get('event') or row.get('Event Type') or 'AUTH_EVENT'
            status = row.get('status') or row.get('Status') or 'Unknown'
            message = row.get('message') or row.get('msg') or row.get('Message') or f"Log entry for user {username}"
            
            # Map status to login success/failed event type if it looks like authentication
            status_lower = status.lower()
            event_type_upper = event_type.upper()
            
            is_failure = 'fail' in status_lower or 'fail' in event_type_upper or event_type_upper == 'LOGIN_FAILED'
            is_success = 'success' in status_lower or 'success' in event_type_upper or event_type_upper == 'LOGIN_SUCCESS'
            
            severity = 'Low'
            mitre_tech = 'N/A'
            mitre_tactic = 'N/A'
            
            if is_failure:
                event_type = 'LOGIN_FAILED'
                status = 'Failure'
                # Increment failed count
                failed_attempts[source_ip] = failed_attempts.get(source_ip, 0) + 1
                severity = self._determine_severity(failed_attempts[source_ip])
                mitre_tech = 'T1110.001 - Brute Force: Password Guessing' if failed_attempts[source_ip] >= 3 else 'T1110 - Brute Force'
                mitre_tactic = 'Credential Access'
            elif is_success:
                event_type = 'LOGIN_SUCCESS'
                status = 'Success'
                severity = 'Low'
                mitre_tech = 'T1078 - Valid Accounts'
                mitre_tactic = 'Defense Evasion / Persistence / Initial Access / Privilege Escalation'
            else:
                # Custom override from row
                severity = row.get('severity') or row.get('Severity') or 'Low'
                mitre_tech = row.get('mitre_technique') or row.get('mitre_tactic') or 'N/A'
                mitre_tactic = row.get('mitre_tactic') or 'N/A'

            country, city = self.geoip_service.resolve(source_ip)
            
            events.append({
                'timestamp': timestamp,
                'event_type': event_type,
                'status': status,
                'source_ip': source_ip,
                'username': username,
                'message': message,
                'severity': severity,
                'mitre_technique': mitre_tech,
                'mitre_tactic': mitre_tactic,
                'country': country,
                'city': city
            })
            
        return events

    def _parse_text(self, content, failed_attempts):
        events = []
        lines = content.splitlines()
        
        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue
                
            # Try to extract timestamp from the beginning of line
            # Common patterns: 'Jun 18 01:11:16', '2026-06-18T01:11:16'
            timestamp = datetime.datetime.utcnow()
            ts_match = re.match(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})', line_str)
            if ts_match:
                timestamp = self._parse_timestamp(ts_match.group(1))
                
            # Default values
            username = 'unknown'
            source_ip = '0.0.0.0'
            event_type = 'SYS_ALERT'
            status = 'Unknown'
            severity = 'Low'
            mitre_tech = 'N/A'
            mitre_tactic = 'N/A'
            message = line_str
            
            # Check SSH Failures
            ssh_fail_match = self.ssh_failed_pattern.search(line_str)
            ssh_success_match = self.ssh_success_pattern.search(line_str)
            
            if ssh_fail_match:
                username = ssh_fail_match.group(1) or 'unknown'
                source_ip = ssh_fail_match.group(2)
                event_type = 'LOGIN_FAILED'
                status = 'Failure'
                
                # Increment failed count
                failed_attempts[source_ip] = failed_attempts.get(source_ip, 0) + 1
                severity = self._determine_severity(failed_attempts[source_ip])
                mitre_tech = 'T1110.001 - Brute Force: Password Guessing' if failed_attempts[source_ip] >= 3 else 'T1110 - Brute Force'
                mitre_tactic = 'Credential Access'
                message = f"SSH authentication failure for user '{username}' from {source_ip}"
                
            elif ssh_success_match:
                username = ssh_success_match.group(1)
                source_ip = ssh_success_match.group(2)
                event_type = 'LOGIN_SUCCESS'
                status = 'Success'
                severity = 'Low'
                mitre_tech = 'T1078 - Valid Accounts'
                mitre_tactic = 'Defense Evasion / Persistence / Initial Access / Privilege Escalation'
                message = f"SSH authentication success for user '{username}' from {source_ip}"
                
            else:
                # Check generic auth patterns
                gen_fail_match = self.generic_fail_pattern.search(line_str)
                gen_success_match = self.generic_success_pattern.search(line_str)
                
                # Try to extract IP anyway
                ip_match = self.ip_pattern.search(line_str)
                extracted_ip = ip_match.group(0) if ip_match else '0.0.0.0'
                
                if gen_fail_match:
                    username = gen_fail_match.group(1) or 'unknown'
                    source_ip = gen_fail_match.group(2) or extracted_ip
                    event_type = 'LOGIN_FAILED'
                    status = 'Failure'
                    
                    failed_attempts[source_ip] = failed_attempts.get(source_ip, 0) + 1
                    severity = self._determine_severity(failed_attempts[source_ip])
                    mitre_tech = 'T1110.001 - Brute Force: Password Guessing' if failed_attempts[source_ip] >= 3 else 'T1110 - Brute Force'
                    mitre_tactic = 'Credential Access'
                    message = f"Authentication failure for user '{username}'"
                elif gen_success_match:
                    username = gen_success_match.group(1) or 'unknown'
                    source_ip = gen_success_match.group(2) or extracted_ip
                    event_type = 'LOGIN_SUCCESS'
                    status = 'Success'
                    severity = 'Low'
                    mitre_tech = 'T1078 - Valid Accounts'
                    mitre_tactic = 'Defense Evasion / Persistence / Initial Access / Privilege Escalation'
                    message = f"Authentication success for user '{username}'"
                else:
                    # Generic log line
                    source_ip = extracted_ip
                    if "error" in line_str.lower() or "critical" in line_str.lower() or "panic" in line_str.lower():
                        severity = 'High'
                        event_type = 'SYS_ERROR'
                        mitre_tech = 'T1499 - Endpoint Denial of Service'
                        mitre_tactic = 'Impact'
                    elif "warning" in line_str.lower():
                        severity = 'Medium'
                        event_type = 'SYS_WARN'
                    else:
                        severity = 'Low'
                        event_type = 'SYS_INFO'
            
            country, city = self.geoip_service.resolve(source_ip)
            
            events.append({
                'timestamp': timestamp,
                'event_type': event_type,
                'status': status,
                'source_ip': source_ip,
                'username': username,
                'message': message,
                'severity': severity,
                'mitre_technique': mitre_tech,
                'mitre_tactic': mitre_tactic,
                'country': country,
                'city': city
            })
            
        return events
