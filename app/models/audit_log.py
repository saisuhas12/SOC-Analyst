import datetime
from app.database import db

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    username = db.Column(db.String(64), nullable=True) # Cache the username in case the user is deleted
    action_type = db.Column(db.String(32), nullable=False) # e.g. 'Login', 'Logout', 'Alert Action', 'Incident Action', 'User Action'
    details = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('audit_logs', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'user_id': self.user_id,
            'username': self.username or 'System',
            'action_type': self.action_type,
            'details': self.details,
            'ip_address': self.ip_address or 'Unknown'
        }
