from flask import Blueprint, render_template, jsonify
from app.models.security_event import SecurityEvent
from app.models.uploaded_log import UploadedLog
from app.models.alert import Alert
from app.models.ioc import IOCIndicator, IOCMatch
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
    
    # Alert and Intelligence statistics
    active_alerts_count = Alert.query.filter(Alert.status.in_(['New', 'Acknowledged'])).count()
    ioc_indicators_count = IOCIndicator.query.count()
    resolved_alerts_count = Alert.query.filter(Alert.status.in_(['Resolved', 'False Positive'])).count()
    total_alerts_count = Alert.query.count()
    
    # Calculate resolution percentage
    if total_alerts_count > 0:
        resolution_rate = int((resolved_alerts_count / total_alerts_count) * 100)
    else:
        resolution_rate = 100
        
    # Recent unresolved high/critical severity alerts
    recent_alerts = Alert.query.filter(
        Alert.status.in_(['New', 'Acknowledged']),
        Alert.severity.in_(['High', 'Critical'])
    ).order_by(Alert.created_at.desc()).limit(8).all()
    
    return render_template(
        'dashboard.html',
        total_logs=total_logs,
        total_events=total_events,
        active_alerts_count=active_alerts_count,
        ioc_indicators_count=ioc_indicators_count,
        resolution_rate=resolution_rate,
        recent_alerts=recent_alerts
    )

@dashboard_bp.route('/api/chart-data')
@login_required
def chart_data():
    """Returns JSON metrics to populate Chart.js components on the dashboard."""
    # 1. Alert Severity Distribution
    sevs = db.session.query(
        Alert.severity, 
        db.func.count(Alert.id)
    ).group_by(Alert.severity).all()
    severity_data = {k: 0 for k in ['Low', 'Medium', 'High', 'Critical']}
    for sev, count in sevs:
        if sev in severity_data:
            severity_data[sev] = count
            
    # 2. Alert Type Distribution (replacing countries chart with alert types for threats over time context)
    types = db.session.query(
        Alert.alert_type, 
        db.func.count(Alert.id)
    ).group_by(Alert.alert_type).order_by(db.func.count(Alert.id).desc()).all()
    
    type_labels = [t[0] for t in types]
    type_counts = [t[1] for t in types]
    
    if not type_labels:
        type_labels = ["No Alerts Available"]
        type_counts = [0]
        
    # 3. Top Attacking Source IPs (based on Alert generation)
    ips = db.session.query(
        Alert.source_ip, 
        db.func.count(Alert.id)
    ).filter(Alert.source_ip != None, Alert.source_ip != '0.0.0.0').group_by(Alert.source_ip).order_by(db.func.count(Alert.id).desc()).limit(5).all()
    
    ip_labels = [i[0] for i in ips]
    ip_counts = [i[1] for i in ips]
    
    if not ip_labels:
        ip_labels = ["No Data Available"]
        ip_counts = [0]

    # 4. Threats over Time: group generated alerts by date (past 7 days) and type
    today = datetime.datetime.utcnow().date()
    date_list = [today - datetime.timedelta(days=x) for x in range(6, -1, -1)]
    date_strs = [d.strftime('%Y-%m-%d') for d in date_list]
    
    timeline_bf = {d: 0 for d in date_strs}  # Brute Force
    timeline_ioc = {d: 0 for d in date_strs} # IOC Match
    timeline_slp = {d: 0 for d in date_strs} # Suspicious Login Pattern
    
    start_date = datetime.datetime.combine(date_list[0], datetime.time.min)
    alerts_7days = Alert.query.filter(
        Alert.created_at >= start_date
    ).all()
    
    for alert in alerts_7days:
        alert_date_str = alert.created_at.strftime('%Y-%m-%d')
        if alert_date_str in timeline_bf:
            if alert.alert_type == 'Brute Force':
                timeline_bf[alert_date_str] += 1
            elif alert.alert_type == 'IOC Match':
                timeline_ioc[alert_date_str] += 1
            elif alert.alert_type == 'Suspicious Login Pattern':
                timeline_slp[alert_date_str] += 1
                
    timeline_data = {
        'labels': [d.strftime('%b %d') for d in date_list],
        'brute_force': [timeline_bf[d] for d in date_strs],
        'ioc_match': [timeline_ioc[d] for d in date_strs],
        'suspicious_login': [timeline_slp[d] for d in date_strs]
    }
    
    return jsonify({
        'severity': {
            'labels': list(severity_data.keys()),
            'counts': list(severity_data.values())
        },
        'types': {
            'labels': type_labels,
            'counts': type_counts
        },
        'ips': {
            'labels': ip_labels,
            'counts': ip_counts
        },
        'timeline': timeline_data
    })
