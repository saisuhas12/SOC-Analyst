import datetime
from app.database import db
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.models.ioc import IOCIndicator, IOCMatch
from app.models.setting import SystemSetting

class DetectionService:
    def __init__(self):
        pass

    def process_events(self, events):
        """
        Processes a list of newly parsed SecurityEvent models.
        Runs Brute Force, Suspicious Login Pattern, and IOC matching detection engines.
        """
        if not events:
            return

        # Flush the session first to ensure all events have IDs assigned
        db.session.flush()

        # Extract unique source IPs for brute force and pattern checking
        source_ips = set(e.source_ip for e in events if e.source_ip and e.source_ip != '0.0.0.0')

        # 1. Run Brute Force & Credential Spraying Detection
        for ip in source_ips:
            self._detect_brute_force(ip)
            self._detect_credential_spraying(ip)

        # 2. Run Suspicious Login Pattern (Success after failure)
        for event in events:
            if event.event_type == 'LOGIN_SUCCESS' and event.source_ip and event.source_ip != '0.0.0.0':
                self._detect_success_after_failure(event)

        # 3. Run IOC Matching
        self._detect_ioc_matches(events)

    def _map_severity_to_priority(self, severity):
        mapping = {
            'Critical': 'P1',
            'High': 'P2',
            'Medium': 'P3',
            'Low': 'P4'
        }
        return mapping.get(severity, 'P3')

    def _get_brute_force_threshold(self):
        val = SystemSetting.get_value('brute_force_threshold', '5')
        try:
            return int(val)
        except ValueError:
            return 5

    def _detect_brute_force(self, ip):
        # Find the latest inactive alert (Resolved / False Positive) to only count attempts since then
        last_inactive = Alert.query.filter(
            Alert.source_ip == ip,
            Alert.alert_type == 'Brute Force',
            Alert.status.in_(['Resolved', 'False Positive'])
        ).order_by(Alert.last_seen.desc()).first()

        since_time = last_inactive.last_seen if last_inactive else None

        # Query failed logins since the last resolved alert
        query = SecurityEvent.query.filter(
            SecurityEvent.source_ip == ip,
            SecurityEvent.event_type == 'LOGIN_FAILED'
        )
        if since_time:
            query = query.filter(SecurityEvent.timestamp > since_time)
        
        failed_logins = query.order_by(SecurityEvent.timestamp.asc()).all()
        count = len(failed_logins)

        threshold = self._get_brute_force_threshold()

        if count >= threshold:
            # Determine dynamic severity & priority
            if count >= threshold * 3:
                severity = 'Critical'
            elif count >= threshold * 2:
                severity = 'High'
            else:
                severity = 'Medium'
            priority = self._map_severity_to_priority(severity)

            # Check if there is an active (New/Acknowledged) brute force alert for this IP
            active_alert = Alert.query.filter(
                Alert.source_ip == ip,
                Alert.alert_type == 'Brute Force',
                Alert.status.in_(['New', 'Acknowledged'])
            ).first()

            if active_alert:
                active_alert.attempt_count = count
                active_alert.last_seen = failed_logins[-1].timestamp
                active_alert.severity = severity
                active_alert.priority = priority
                active_alert.description = f"Brute force detection: {count} failed login attempts from IP {ip}."
            else:
                new_alert = Alert(
                    alert_type='Brute Force',
                    severity=severity,
                    priority=priority,
                    status='New',
                    source_ip=ip,
                    attempt_count=count,
                    first_seen=failed_logins[0].timestamp,
                    last_seen=failed_logins[-1].timestamp,
                    description=f"Brute force detection: {count} failed login attempts from IP {ip}.",
                    mitre_technique="T1110.001 - Brute Force: Password Guessing",
                    mitre_tactic="Credential Access"
                )
                db.session.add(new_alert)

    def _detect_credential_spraying(self, ip):
        # Look for failed logins targeting distinct usernames from the same IP
        last_inactive = Alert.query.filter(
            Alert.source_ip == ip,
            Alert.alert_type == 'Suspicious Login Pattern',
            Alert.description.like('%Credential spraying%'),
            Alert.status.in_(['Resolved', 'False Positive'])
        ).order_by(Alert.last_seen.desc()).first()

        since_time = last_inactive.last_seen if last_inactive else None

        query = SecurityEvent.query.filter(
            SecurityEvent.source_ip == ip,
            SecurityEvent.event_type == 'LOGIN_FAILED'
        )
        if since_time:
            query = query.filter(SecurityEvent.timestamp > since_time)

        events = query.all()
        if not events:
            return

        usernames = set(e.username for e in events if e.username and e.username != 'unknown')
        if len(usernames) >= 3:
            # In credential spraying, multiple accounts are targeted
            severity = 'High'
            priority = 'P2'
            
            # Check for existing active alert
            active_alert = Alert.query.filter(
                Alert.source_ip == ip,
                Alert.alert_type == 'Suspicious Login Pattern',
                Alert.description.like('%Credential spraying%'),
                Alert.status.in_(['New', 'Acknowledged'])
            ).first()

            timestamps = [e.timestamp for e in events]
            first_seen = min(timestamps)
            last_seen = max(timestamps)

            desc = f"Suspicious Login Pattern: Credential spraying detected from IP {ip} targeting {len(usernames)} distinct usernames ({', '.join(list(usernames)[:5])})."

            if active_alert:
                active_alert.attempt_count = len(events)
                active_alert.last_seen = last_seen
                active_alert.severity = severity
                active_alert.priority = priority
                active_alert.description = desc
            else:
                new_alert = Alert(
                    alert_type='Suspicious Login Pattern',
                    severity=severity,
                    priority=priority,
                    status='New',
                    source_ip=ip,
                    attempt_count=len(events),
                    first_seen=first_seen,
                    last_seen=last_seen,
                    description=desc,
                    mitre_technique="T1110.003 - Brute Force: Credential Spraying",
                    mitre_tactic="Credential Access"
                )
                db.session.add(new_alert)

    def _detect_success_after_failure(self, event):
        # Look for any failed logins from the same IP within 2 hours before the success event
        start_window = event.timestamp - datetime.timedelta(hours=2)

        failed_count = SecurityEvent.query.filter(
            SecurityEvent.source_ip == event.source_ip,
            SecurityEvent.event_type == 'LOGIN_FAILED',
            SecurityEvent.timestamp >= start_window,
            SecurityEvent.timestamp < event.timestamp
        ).count()

        if failed_count >= 3:
            # That's a highly dangerous alert: success after brute forcing!
            severity = 'Critical'
            priority = 'P1'
            
            # Check if active alert already exists for this compromise
            active_alert = Alert.query.filter(
                Alert.source_ip == event.source_ip,
                Alert.alert_type == 'Suspicious Login Pattern',
                Alert.description.like('%compromise%'),
                Alert.status.in_(['New', 'Acknowledged'])
            ).first()

            desc = f"Suspicious Login Pattern: Successful login for user '{event.username}' from IP {event.source_ip} following {failed_count} authentication failures. Potential compromise!"

            if active_alert:
                # Update attempts
                active_alert.last_seen = event.timestamp
                active_alert.description = desc
            else:
                new_alert = Alert(
                    alert_type='Suspicious Login Pattern',
                    severity=severity,
                    priority=priority,
                    status='New',
                    source_ip=event.source_ip,
                    attempt_count=failed_count + 1,
                    first_seen=event.timestamp - datetime.timedelta(minutes=30), # estimate
                    last_seen=event.timestamp,
                    description=desc,
                    mitre_technique="T1110 - Brute Force",
                    mitre_tactic="Credential Access / Initial Access"
                )
                db.session.add(new_alert)

    def _detect_ioc_matches(self, events):
        indicators = IOCIndicator.query.all()
        if not indicators:
            return

        for event in events:
            for ind in indicators:
                matched = False
                matched_val = ind.value
                
                if ind.ioc_type == 'IP Address':
                    if event.source_ip == ind.value:
                        matched = True
                    elif event.message and ind.value in event.message:
                        matched = True
                else:  # Domain, URL, File Hash
                    if event.message and ind.value.lower() in event.message.lower():
                        matched = True
                    if event.username and ind.value.lower() in event.username.lower():
                        matched = True
                
                if matched:
                    # 1. Store IOC Match record
                    ioc_match = IOCMatch(
                        ioc_indicator_id=ind.id,
                        security_event_id=event.id,
                        matched_value=matched_val,
                        matched_at=datetime.datetime.utcnow(),
                        details=f"Threat event matched in log parsing. Message: {event.message}"
                    )
                    db.session.add(ioc_match)
                    
                    # 2. Map MITRE ATT&CK techniques based on IOC type
                    mitre_tech = "T1071 - Standard Application Layer Protocol"
                    mitre_tactic = "Command and Control"
                    if ind.ioc_type == 'Domain' or ind.ioc_type == 'URL':
                        mitre_tech = "T1566 - Phishing"
                        mitre_tactic = "Initial Access"
                    elif ind.ioc_type == 'File Hash':
                        mitre_tech = "T1204.002 - User Execution: Malicious File"
                        mitre_tactic = "Execution"

                    priority = self._map_severity_to_priority(ind.severity)

                    # 3. Check for existing active alert for this IOC + IP to prevent duplicates
                    active_alert = Alert.query.filter(
                        Alert.ioc_indicator_id == ind.id,
                        Alert.source_ip == event.source_ip,
                        Alert.status.in_(['New', 'Acknowledged'])
                    ).first()

                    desc = f"IOC Match: matched threat indicator '{ind.value}' ({ind.ioc_type}) on IP {event.source_ip}."

                    if active_alert:
                        active_alert.last_seen = event.timestamp
                        active_alert.attempt_count = (active_alert.attempt_count or 1) + 1
                    else:
                        new_alert = Alert(
                            alert_type='IOC Match',
                            severity=ind.severity,
                            priority=priority,
                            status='New',
                            source_ip=event.source_ip,
                            attempt_count=1,
                            first_seen=event.timestamp,
                            last_seen=event.timestamp,
                            ioc_indicator_id=ind.id,
                            description=desc,
                            mitre_technique=mitre_tech,
                            mitre_tactic=mitre_tactic
                        )
                        db.session.add(new_alert)
