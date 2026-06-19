import datetime
from app.database import db

class IOCIndicator(db.Model):
    __tablename__ = 'ioc_indicators'
    
    id = db.Column(db.Integer, primary_key=True)
    ioc_type = db.Column(db.String(64), nullable=False, index=True)  # 'IP Address', 'Domain', 'URL', 'File Hash'
    value = db.Column(db.String(256), nullable=False, unique=True, index=True)
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(16), default='Medium', nullable=False, index=True)  # 'Low', 'Medium', 'High', 'Critical'
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    # Relationships
    creator = db.relationship('User', backref=db.backref('ioc_indicators', lazy=True))
    matches = db.relationship('IOCMatch', backref='indicator', lazy=True, cascade='all, delete-orphan')
    alerts = db.relationship('Alert', backref='ioc_indicator', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'ioc_type': self.ioc_type,
            'value': self.value,
            'description': self.description or '',
            'severity': self.severity,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.creator.username if self.creator else 'Unknown'
        }

class IOCMatch(db.Model):
    __tablename__ = 'ioc_matches'
    
    id = db.Column(db.Integer, primary_key=True)
    ioc_indicator_id = db.Column(db.Integer, db.ForeignKey('ioc_indicators.id', ondelete='CASCADE'), nullable=False)
    security_event_id = db.Column(db.Integer, db.ForeignKey('security_events.id', ondelete='CASCADE'), nullable=True)
    matched_value = db.Column(db.String(256), nullable=False, index=True)
    matched_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False, index=True)
    details = db.Column(db.Text, nullable=True)
    
    # Relationships
    event = db.relationship('SecurityEvent', backref=db.backref('ioc_matches', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'ioc_indicator_id': self.ioc_indicator_id,
            'ioc_type': self.indicator.ioc_type if self.indicator else 'Unknown',
            'ioc_value': self.indicator.value if self.indicator else 'Unknown',
            'security_event_id': self.security_event_id,
            'matched_value': self.matched_value,
            'matched_at': self.matched_at.isoformat() if self.matched_at else None,
            'details': self.details or '',
            'source_ip': self.event.source_ip if self.event else 'N/A'
        }
