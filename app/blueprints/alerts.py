import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.database import db
from app.models.alert import Alert
from app.models.user import User
from app.utils.decorators import login_required, role_required
from app.utils.audit import log_audit_event

alerts_bp = Blueprint('alerts', __name__)

@alerts_bp.route('/alerts')
@login_required
def index():
    # Retrieve query params
    alert_type = request.args.get('alert_type', '').strip()
    severity = request.args.get('severity', '').strip()
    priority = request.args.get('priority', '').strip()
    status = request.args.get('status', '').strip()
    
    # Build query
    query = Alert.query
    
    if alert_type and alert_type != 'ALL':
        query = query.filter(Alert.alert_type == alert_type)
    if severity and severity != 'ALL':
        query = query.filter(Alert.severity == severity)
    if priority and priority != 'ALL':
        query = query.filter(Alert.priority == priority)
    if status and status != 'ALL':
        query = query.filter(Alert.status == status)
        
    alerts_list = query.order_by(Alert.created_at.desc()).all()
    
    # Extract unique types and list of analysts for dropdowns
    all_users = User.query.order_by(User.username.asc()).all()
    alert_types = ['Brute Force', 'IOC Match', 'Suspicious Login Pattern', 'Suspicious Activity']
    
    return render_template(
        'alerts.html',
        alerts=alerts_list,
        users=all_users,
        alert_types=alert_types,
        filters=request.args
    )

@alerts_bp.route('/alerts/acknowledge/<int:alert_id>', methods=['POST'])
@login_required
@role_required('admin', 'analyst')
def acknowledge(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.status = 'Acknowledged'
    try:
        db.session.commit()
        log_audit_event('Alert Action', f"Acknowledged Alert #{alert.id} ({alert.alert_type}, Severity: {alert.severity})")
        flash(f"Alert #{alert.id} status updated to Acknowledged.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error updating alert: {str(e)}", "danger")
    return redirect(url_for('alerts.index'))

@alerts_bp.route('/alerts/resolve/<int:alert_id>', methods=['POST'])
@login_required
@role_required('admin', 'analyst')
def resolve(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.status = 'Resolved'
    alert.resolved_at = datetime.datetime.utcnow()
    try:
        db.session.commit()
        log_audit_event('Alert Action', f"Resolved Alert #{alert.id} ({alert.alert_type})")
        flash(f"Alert #{alert.id} resolved successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error resolving alert: {str(e)}", "danger")
    return redirect(url_for('alerts.index'))

@alerts_bp.route('/alerts/false-positive/<int:alert_id>', methods=['POST'])
@login_required
@role_required('admin', 'analyst')
def false_positive(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.status = 'False Positive'
    alert.resolved_at = datetime.datetime.utcnow()
    try:
        db.session.commit()
        log_audit_event('Alert Action', f"Classified Alert #{alert.id} ({alert.alert_type}) as False Positive")
        flash(f"Alert #{alert.id} classified as False Positive.", "warning")
    except Exception as e:
        db.session.rollback()
        flash(f"Error updating alert: {str(e)}", "danger")
    return redirect(url_for('alerts.index'))

@alerts_bp.route('/alerts/assign/<int:alert_id>', methods=['POST'])
@login_required
@role_required('admin', 'analyst')
def assign(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    user_id_str = request.form.get('assigned_to_id', '').strip()
    
    if not user_id_str or user_id_str == '0':
        alert.assigned_to_id = None
        assigned_name = "Unassigned"
    else:
        try:
            user_id = int(user_id_str)
            user = User.query.get_or_404(user_id)
            alert.assigned_to_id = user.id
            assigned_name = user.username
        except ValueError:
            flash("Invalid analyst ID.", "danger")
            return redirect(url_for('alerts.index'))
            
    try:
        db.session.commit()
        log_audit_event('Alert Action', f"Assigned Alert #{alert.id} ({alert.alert_type}) to {assigned_name}")
        flash(f"Alert #{alert.id} assigned to {assigned_name}.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error assigning alert: {str(e)}", "danger")
        
    return redirect(url_for('alerts.index'))
