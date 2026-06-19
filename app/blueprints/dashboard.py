from flask import Blueprint, render_template, jsonify
from app.models.security_event import SecurityEvent
from app.models.uploaded_log import UploadedLog
from app.database import db
from app.utils.decorators import login_required
from collections import defaultdict
import datetime

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@dashboard_bp.route('/dashboard')
@login_required
def index():
    # Summary stats
    total_logs = db.session.query(db.func.sum(UploadedLog.log_count)).scalar() or 0
    total_events = SecurityEvent.query.count()
    failed_logins = SecurityEvent.query.filter_by(event_type='LOGIN_FAILED').count()
    successful_logins = SecurityEvent.query.filter_by(event_type='LOGIN_SUCCESS').count()
    
    # Suspicious IPs: source IPs with 3 or more failed login attempts
    suspicious_ips_query = db.session.query(
        SecurityEvent.source_ip, 
        db.func.count(SecurityEvent.id).label('fail_count')
    ).filter_by(event_type='LOGIN_FAILED').group_by(SecurityEvent.source_ip).having(db.func.count(SecurityEvent.id) >= 3)
    
    suspicious_ip_count = suspicious_ips_query.count()
    
    # Security alerts: any event with severity Medium, High, or Critical
    security_alerts_count = SecurityEvent.query.filter(SecurityEvent.severity.in_(['Medium', 'High', 'Critical'])).count()
    
    # Recent high/critical severity alerts
    recent_alerts = SecurityEvent.query.filter(SecurityEvent.severity.in_(['High', 'Critical'])).order_by(SecurityEvent.timestamp.desc()).limit(8).all()
    
    return render_template(
        'dashboard.html',
        total_logs=total_logs,
        total_events=total_events,
        failed_logins=failed_logins,
        successful_logins=successful_logins,
        suspicious_ip_count=suspicious_ip_count,
        security_alerts_count=security_alerts_count,
        recent_alerts=recent_alerts
    )

@dashboard_bp.route('/api/chart-data')
@login_required
def chart_data():
    """Returns JSON metrics to populate Chart.js components on the dashboard."""
    # 1. Severity Breakdown
    sevs = db.session.query(
        SecurityEvent.severity, 
        db.func.count(SecurityEvent.id)
    ).group_by(SecurityEvent.severity).all()
    severity_data = {k: 0 for k in ['Low', 'Medium', 'High', 'Critical']}
    for sev, count in sevs:
        if sev in severity_data:
            severity_data[sev] = count
            
    # 2. Top Attacking Countries (based on LOGIN_FAILED events)
    countries = db.session.query(
        SecurityEvent.country, 
        db.func.count(SecurityEvent.id)
    ).filter(SecurityEvent.event_type == 'LOGIN_FAILED').group_by(SecurityEvent.country).order_by(db.func.count(SecurityEvent.id).desc()).limit(5).all()
    
    country_labels = [c[0] if c[0] else 'Unknown' for c in countries]
    country_counts = [c[1] for c in countries]
    
    # If no data, fill with placeholders so UI charts load beautifully
    if not country_labels:
        country_labels = ["No Data Available"]
        country_counts = [0]
        
    # 3. Top Attacking Source IPs (based on LOGIN_FAILED events)
    ips = db.session.query(
        SecurityEvent.source_ip, 
        db.func.count(SecurityEvent.id)
    ).filter(SecurityEvent.event_type == 'LOGIN_FAILED').group_by(SecurityEvent.source_ip).order_by(db.func.count(SecurityEvent.id).desc()).limit(5).all()
    
    ip_labels = [i[0] for i in ips]
    ip_counts = [i[1] for i in ips]
    
    if not ip_labels:
        ip_labels = ["No Data Available"]
        ip_counts = [0]

    # 4. Threat Timeline: group total failed and successful events by date (past 7 days)
    today = datetime.datetime.utcnow().date()
    date_list = [today - datetime.timedelta(days=x) for x in range(6, -1, -1)]
    date_strs = [d.strftime('%Y-%m-%d') for d in date_list]
    
    timeline_fails = {d: 0 for d in date_strs}
    timeline_success = {d: 0 for d in date_strs}
    
    # Query events from the last 7 days
    start_date = datetime.datetime.combine(date_list[0], datetime.time.min)
    events_7days = SecurityEvent.query.filter(
        SecurityEvent.timestamp >= start_date,
        SecurityEvent.event_type.in_(['LOGIN_FAILED', 'LOGIN_SUCCESS'])
    ).all()
    
    for event in events_7days:
        evt_date_str = event.timestamp.strftime('%Y-%m-%d')
        if evt_date_str in timeline_fails:
            if event.event_type == 'LOGIN_FAILED':
                timeline_fails[evt_date_str] += 1
            elif event.event_type == 'LOGIN_SUCCESS':
                timeline_success[evt_date_str] += 1
                
    timeline_data = {
        'labels': [d.strftime('%b %d') for d in date_list],
        'failed': [timeline_fails[d] for d in date_strs],
        'success': [timeline_success[d] for d in date_strs]
    }
    
    return jsonify({
        'severity': {
            'labels': list(severity_data.keys()),
            'counts': list(severity_data.values())
        },
        'countries': {
            'labels': country_labels,
            'counts': country_counts
        },
        'ips': {
            'labels': ip_labels,
            'counts': ip_counts
        },
        'timeline': timeline_data
    })
