import datetime
from app.database import db

class Alert(db.Model):
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(64), nullable=False, index=True)  # 'Brute Force', 'IOC Match', 'Suspicious Login Pattern', 'Suspicious Activity'
    severity = db.Column(db.String(16), nullable=False, index=True)  # 'Low', 'Medium', 'High', 'Critical'
    priority = db.Column(db.String(8), nullable=False, default='P3', index=True)  # 'P1', 'P2', 'P3', 'P4'
    status = db.Column(db.String(32), default='New', nullable=False, index=True)  # 'New', 'Acknowledged', 'Resolved', 'False Positive'
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False, index=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    description = db.Column(db.Text, nullable=True)
    
    # Brute Force / Pattern specific
    source_ip = db.Column(db.String(45), nullable=True, index=True)
    attempt_count = db.Column(db.Integer, nullable=True)
    first_seen = db.Column(db.DateTime, nullable=True)
    last_seen = db.Column(db.DateTime, nullable=True)
    
    # IOC specific
    ioc_indicator_id = db.Column(db.Integer, db.ForeignKey('ioc_indicators.id', ondelete='SET NULL'), nullable=True)
    
    # MITRE ATT&CK Mapping
    mitre_technique = db.Column(db.String(64), nullable=True)  # e.g., T1110.001 - Password Guessing
    mitre_tactic = db.Column(db.String(64), nullable=True)     # e.g., Credential Access
    
    # Relationships
    assigned_user = db.relationship('User', backref=db.backref('alerts', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'priority': self.priority,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'assigned_to': self.assigned_user.username if self.assigned_user else 'Unassigned',
            'assigned_to_id': self.assigned_to_id,
            'description': self.description or '',
            'source_ip': self.source_ip or 'N/A',
            'attempt_count': self.attempt_count,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'ioc_indicator_id': self.ioc_indicator_id,
            'mitre_technique': self.mitre_technique or 'N/A',
            'mitre_tactic': self.mitre_tactic or 'N/A'
        }
