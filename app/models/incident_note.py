import datetime
from app.database import db

class IncidentNote(db.Model):
    __tablename__ = 'incident_notes'
    
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    note_text = db.Column(db.Text, nullable=False)
    screenshot_path = db.Column(db.String(256), nullable=True) # stores relative path to uploads
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    
    # Relationships
    author = db.relationship('User', backref=db.backref('incident_notes', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'incident_id': self.incident_id,
            'user_id': self.user_id,
            'author': self.author.username if self.author else 'Unknown User',
            'note_text': self.note_text,
            'screenshot_path': self.screenshot_path,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
