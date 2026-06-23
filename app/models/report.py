import datetime
import json
from app.database import db

class Report(db.Model):
    __tablename__ = 'reports'
    
    id = db.Column(db.Integer, primary_key=True)
    report_type = db.Column(db.String(64), nullable=False) # 'Daily SOC Report', 'Threat Summary Report', 'IOC Match Report', 'Incident Investigation Report'
    title = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    
    executive_summary = db.Column(db.Text, nullable=True)
    findings = db.Column(db.Text, nullable=True)
    recommendations = db.Column(db.Text, nullable=True)
    
    # Store chart metrics as a JSON-serialised string
    charts_data_json = db.Column(db.Text, name='charts_data', default='{}', nullable=False)
    pdf_path = db.Column(db.String(256), nullable=False) # relative web-accessible static path
    
    # Relationship
    creator = db.relationship('User', backref=db.backref('reports', lazy=True))
    
    @property
    def charts_data(self):
        try:
            return json.loads(self.charts_data_json or '{}')
        except Exception:
            return {}
            
    @charts_data.setter
    def charts_data(self, value):
        self.charts_data_json = json.dumps(value)
        
    def to_dict(self):
        return {
            'id': self.id,
            'report_type': self.report_type,
            'title': self.title,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.creator.username if self.creator else 'System',
            'created_by_id': self.created_by_id,
            'executive_summary': self.executive_summary or '',
            'findings': self.findings or '',
            'recommendations': self.recommendations or '',
            'charts_data': self.charts_data,
            'pdf_path': self.pdf_path
        }
