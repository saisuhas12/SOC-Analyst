import datetime
import json
from app.database import db

class Incident(db.Model):
    __tablename__ = 'incidents'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(16), nullable=False, default='Medium')  # 'Low', 'Medium', 'High', 'Critical'
    status = db.Column(db.String(32), nullable=False, default='Open')      # 'Open', 'Investigating', 'Resolved', 'Closed'
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id', ondelete='SET NULL'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)
    
    # Store the timeline as a JSON-serialised string in a text column
    timeline_json = db.Column(db.Text, name='timeline', default='[]', nullable=False)
    
    # Relationships
    assigned_user = db.relationship('User', backref=db.backref('incidents', lazy=True))
    alert = db.relationship('Alert', backref=db.backref('incidents', lazy=True))
    notes = db.relationship('IncidentNote', backref='incident', lazy=True, cascade="all, delete-orphan")
    
    @property
    def timeline(self):
        try:
            return json.loads(self.timeline_json or '[]')
        except Exception:
            return []
            
    @timeline.setter
    def timeline(self, value):
        self.timeline_json = json.dumps(value)
        
    def add_timeline_event(self, message, username):
        events = self.timeline
        events.append({
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'message': message,
            'user': username
        })
        self.timeline = events

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description or '',
            'severity': self.severity,
            'status': self.status,
            'assigned_to_id': self.assigned_to_id,
            'assigned_to': self.assigned_user.username if self.assigned_user else 'Unassigned',
            'alert_id': self.alert_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'timeline': self.timeline
        }
