import os
import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app, send_from_directory
from werkzeug.utils import secure_filename
from app.database import db
from app.models.incident import Incident
from app.models.incident_note import IncidentNote
from app.models.alert import Alert
from app.models.user import User
from app.utils.decorators import role_required, login_required
from app.utils.audit import log_audit_event

incidents_bp = Blueprint('incidents', __name__)

ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[-1].lower() in ALLOWED_IMAGE_EXTENSIONS

@incidents_bp.route('/incidents')
@login_required
@role_required('admin', 'analyst', 'viewer')
def index():
    status_filter = request.args.get('status', '').strip()
    severity_filter = request.args.get('severity', '').strip()
    
    query = Incident.query
    if status_filter and status_filter != 'ALL':
        query = query.filter(Incident.status == status_filter)
    if severity_filter and severity_filter != 'ALL':
        query = query.filter(Incident.severity == severity_filter)
        
    incidents_list = query.order_by(Incident.created_at.desc()).all()
    all_users = User.query.order_by(User.username.asc()).all()
    
    return render_template(
        'incidents.html',
        incidents=incidents_list,
        users=all_users,
        filters=request.args
    )

@incidents_bp.route('/incidents/create', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'analyst')
def create():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        severity = request.form.get('severity', 'Medium').strip()
        assigned_to_id_str = request.form.get('assigned_to_id', '').strip()
        alert_id_str = request.form.get('alert_id', '').strip()
        
        if not title:
            flash('Incident Title is required.', 'danger')
            return redirect(url_for('incidents.create', alert_id=alert_id_str))
            
        assigned_to_id = None
        if assigned_to_id_str and assigned_to_id_str != '0':
            assigned_to_id = int(assigned_to_id_str)
            
        alert_id = None
        if alert_id_str:
            alert_id = int(alert_id_str)
            
        # Create incident
        incident = Incident(
            title=title,
            description=description,
            severity=severity,
            status='Open',
            assigned_to_id=assigned_to_id,
            alert_id=alert_id
        )
        
        # Timeline creation event
        username = session.get('username', 'System')
        incident.add_timeline_event("Incident created.", username)
        
        # Link Alert actions
        if alert_id:
            alert = Alert.query.get(alert_id)
            if alert:
                # auto acknowledge the alert if it's new
                if alert.status == 'New':
                    alert.status = 'Acknowledged'
                # assign alert to the same analyst if not already assigned
                if assigned_to_id and not alert.assigned_to_id:
                    alert.assigned_to_id = assigned_to_id
                incident.add_timeline_event(f"Linked to Alert #{alert.id} ({alert.alert_type}).", username)
                
        try:
            db.session.add(incident)
            db.session.commit()
            log_audit_event('Incident Action', f"Created Incident #{incident.id}: '{incident.title}' (Severity: {incident.severity})")
            flash(f"Incident #{incident.id} has been successfully created.", "success")
            return redirect(url_for('incidents.detail', incident_id=incident.id))
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating incident: {str(e)}", "danger")
            return redirect(url_for('incidents.create', alert_id=alert_id_str))
            
    # GET request
    alert_id = request.args.get('alert_id')
    prefill = {}
    if alert_id:
        alert = Alert.query.get(alert_id)
        if alert:
            prefill = {
                'alert_id': alert.id,
                'title': f"Incident from Alert #{alert.id}: {alert.alert_type}",
                'severity': alert.severity,
                'description': f"Triggered from Alert #{alert.id}.\nAlert Type: {alert.alert_type}\nSeverity: {alert.severity}\nSource IP: {alert.source_ip}\nMITRE ATT&CK Tactic: {alert.mitre_tactic or 'N/A'}\nDescription: {alert.description or 'N/A'}",
                'assigned_to_id': alert.assigned_to_id
            }
            
    all_users = User.query.order_by(User.username.asc()).all()
    return render_template('incident_create.html', users=all_users, prefill=prefill)

@incidents_bp.route('/incidents/<int:incident_id>')
@login_required
@role_required('admin', 'analyst', 'viewer')
def detail(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    all_users = User.query.order_by(User.username.asc()).all()
    
    # Sort notes by created_at desc
    notes = IncidentNote.query.filter_by(incident_id=incident.id).order_by(IncidentNote.created_at.desc()).all()
    
    return render_template('incident_detail.html', incident=incident, users=all_users, notes=notes)

@incidents_bp.route('/incidents/<int:incident_id>/edit', methods=['POST'])
@login_required
@role_required('admin', 'analyst')
def edit(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    username = session.get('username', 'System')
    
    severity = request.form.get('severity', incident.severity).strip()
    status = request.form.get('status', incident.status).strip()
    assigned_to_id_str = request.form.get('assigned_to_id', '').strip()
    
    assigned_to_id = None
    if assigned_to_id_str and assigned_to_id_str != '0':
        assigned_to_id = int(assigned_to_id_str)
        
    changes = []
    
    # Track Severity changes
    if incident.severity != severity:
        changes.append(f"Severity updated from '{incident.severity}' to '{severity}'")
        incident.severity = severity
        
    # Track Status changes
    if incident.status != status:
        changes.append(f"Status updated from '{incident.status}' to '{status}'")
        incident.status = status
        
    # Track Assignment changes
    if incident.assigned_to_id != assigned_to_id:
        old_user = incident.assigned_user.username if incident.assigned_user else 'Unassigned'
        new_user_obj = User.query.get(assigned_to_id) if assigned_to_id else None
        new_user = new_user_obj.username if new_user_obj else 'Unassigned'
        changes.append(f"Assigned analyst updated from '{old_user}' to '{new_user}'")
        incident.assigned_to_id = assigned_to_id
        
    if changes:
        # Add timeline entries
        for change in changes:
            incident.add_timeline_event(change, username)
            
        try:
            db.session.commit()
            # Log single aggregated audit event
            log_audit_event('Incident Action', f"Updated Incident #{incident.id}: {', '.join(changes)}")
            flash(f"Incident #{incident.id} updated successfully.", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error saving changes: {str(e)}", "danger")
    else:
        flash("No changes detected.", "info")
        
    return redirect(url_for('incidents.detail', incident_id=incident.id))

@incidents_bp.route('/incidents/<int:incident_id>/notes', methods=['POST'])
@login_required
@role_required('admin', 'analyst')
def add_note(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    note_text = request.form.get('note_text', '').strip()
    username = session.get('username', 'System')
    
    if not note_text:
        flash('Note content cannot be empty.', 'danger')
        return redirect(url_for('incidents.detail', incident_id=incident.id))
        
    screenshot_path = None
    screenshot_file = request.files.get('screenshot')
    
    if screenshot_file and screenshot_file.filename != '':
        if allowed_file(screenshot_file.filename):
            # Ensure upload screenshots directory exists
            screenshots_dir = os.path.join(current_app.static_folder, 'uploads', 'screenshots')
            os.makedirs(screenshots_dir, exist_ok=True)
            
            sec_filename = secure_filename(screenshot_file.filename)
            timestamp_prefix = datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S_')
            unique_filename = timestamp_prefix + sec_filename
            file_path = os.path.join(screenshots_dir, unique_filename)
            
            try:
                screenshot_file.save(file_path)
                # Store Web-accessible relative path starting with 'uploads/screenshots/'
                screenshot_path = f"uploads/screenshots/{unique_filename}"
            except Exception as e:
                flash(f"Error saving screenshot upload: {str(e)}", "danger")
                return redirect(url_for('incidents.detail', incident_id=incident.id))
        else:
            flash('Invalid image format. Allowed formats: PNG, JPG, JPEG, GIF, WEBP.', 'danger')
            return redirect(url_for('incidents.detail', incident_id=incident.id))
            
    try:
        note = IncidentNote(
            incident_id=incident.id,
            user_id=session.get('user_id'),
            note_text=note_text,
            screenshot_path=screenshot_path
        )
        db.session.add(note)
        
        # Add event to incident timeline
        timeline_msg = "Added analyst investigation note."
        if screenshot_path:
            timeline_msg += " (Screenshot attached)"
        incident.add_timeline_event(timeline_msg, username)
        
        db.session.commit()
        log_audit_event('Incident Action', f"Added note to Incident #{incident.id} (Has screenshot: {bool(screenshot_path)})")
        flash("Investigation note successfully posted.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to post note: {str(e)}", "danger")
        
    return redirect(url_for('incidents.detail', incident_id=incident.id))
