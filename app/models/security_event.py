import datetime
from app.database import db

class SecurityEvent(db.Model):
    __tablename__ = 'security_events'
    
    id = db.Column(db.Integer, primary_key=True)
    uploaded_log_id = db.Column(db.Integer, db.ForeignKey('uploaded_logs.id', ondelete='CASCADE'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False, index=True)
    event_type = db.Column(db.String(64), nullable=False, index=True)  # LOGIN_FAILED, LOGIN_SUCCESS, etc.
    status = db.Column(db.String(32), nullable=False)  # Success, Failure
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    username = db.Column(db.String(64), nullable=True, index=True)
    message = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(16), nullable=False, index=True)  # Low, Medium, High, Critical
    
    # MITRE ATT&CK Mapping
    mitre_technique = db.Column(db.String(64), nullable=True)  # e.g., T1110 - Brute Force
    mitre_tactic = db.Column(db.String(64), nullable=True)     # e.g., Credential Access
    
    # GeoIP Information
    country = db.Column(db.String(64), nullable=True, default='Unknown')
    city = db.Column(db.String(64), nullable=True, default='Unknown')

    def to_dict(self):
        return {
            'id': self.id,
            'uploaded_log_id': self.uploaded_log_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'event_type': self.event_type,
            'status': self.status,
            'source_ip': self.source_ip,
            'username': self.username or '',
            'message': self.message or '',
            'severity': self.severity,
            'mitre_technique': self.mitre_technique or 'N/A',
            'mitre_tactic': self.mitre_tactic or 'N/A',
            'country': self.country or 'Unknown',
            'city': self.city or 'Unknown'
        }
