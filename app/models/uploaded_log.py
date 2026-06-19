import datetime
from app.database import db

class UploadedLog(db.Model):
    __tablename__ = 'uploaded_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    file_size = db.Column(db.Integer, nullable=False)  # Size in bytes
    log_count = db.Column(db.Integer, default=0, nullable=False)  # Parsed lines
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    # Relationships
    events = db.relationship('SecurityEvent', backref='log_source', lazy=True, cascade="all, delete-orphan")
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'upload_time': self.upload_time.isoformat() if self.upload_time else None,
            'file_size': self.file_size,
            'log_count': self.log_count,
            'uploaded_by': self.uploader.username if self.uploader else 'Unknown'
        }
