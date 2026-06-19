import os
import csv
import io
import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app, Response, send_file
from werkzeug.utils import secure_filename
from app.database import db
from app.models.uploaded_log import UploadedLog
from app.models.security_event import SecurityEvent
from app.utils.decorators import login_required
from app.services.geoip_service import GeoIPService
from app.services.parser_service import LogParserService

main_bp = Blueprint('main', __name__)

def get_services():
    # Instantiate or fetch services
    # Config has path to GeoLite2 DB
    db_path = current_app.config.get('GEOLITE2_DB_PATH')
    geoip_service = GeoIPService(db_path)
    parser_service = LogParserService(geoip_service)
    return geoip_service, parser_service

@main_bp.route('/uploads', methods=['GET', 'POST'])
@login_required
def uploads():
    if request.method == 'POST':
        if 'files' not in request.files:
            flash('No file part in the request.', 'danger')
            return redirect(request.url)
            
        files = request.files.getlist('files')
        if not files or files[0].filename == '':
            flash('No files selected for upload.', 'danger')
            return redirect(request.url)
            
        geoip_service, parser_service = get_services()
        
        # Ensure uploads folder exists
        os.makedirs(current_app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        successful_uploads = 0
        total_events_parsed = 0
        
        for file in files:
            filename = file.filename
            # Validate extension
            ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
            if ext not in current_app.config['ALLOWED_EXTENSIONS']:
                flash(f'File "{filename}" has an invalid extension. Only .txt, .csv, and .log are allowed.', 'danger')
                continue
                
            sec_filename = secure_filename(filename)
            # Add unique prefix to avoid collisions
            timestamp_prefix = datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S_')
            unique_filename = timestamp_prefix + sec_filename
            file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
            
            try:
                # Read content and save file
                file_bytes = file.read()
                
                # Run the Log Analysis Engine
                parsed_events = parser_service.parse_file(filename, file_bytes)
                
                # Save physical file
                with open(file_path, 'wb') as f:
                    f.write(file_bytes)
                    
                # Save UploadedLog metadata
                uploaded_log = UploadedLog(
                    filename=filename,
                    file_size=len(file_bytes),
                    log_count=len(parsed_events),
                    user_id=session['user_id']
                )
                db.session.add(uploaded_log)
                db.session.flush()  # Extract the ID
                
                # Save parsed events
                for event in parsed_events:
                    se = SecurityEvent(
                        uploaded_log_id=uploaded_log.id,
                        timestamp=event['timestamp'],
                        event_type=event['event_type'],
                        status=event['status'],
                        source_ip=event['source_ip'],
                        username=event['username'],
                        message=event['message'],
                        severity=event['severity'],
                        mitre_technique=event['mitre_technique'],
                        mitre_tactic=event['mitre_tactic'],
                        country=event['country'],
                        city=event['city']
                    )
                    db.session.add(se)
                    
                db.session.commit()
                successful_uploads += 1
                total_events_parsed += len(parsed_events)
                
            except Exception as e:
                db.session.rollback()
                flash(f'Error processing file "{filename}": {str(e)}', 'danger')
                
        # Clean up geoip reader
        geoip_service.close()
        
        if successful_uploads > 0:
            flash(f'Successfully analyzed {successful_uploads} log file(s). Parsed {total_events_parsed} security events.', 'success')
            
        return redirect(url_for('main.uploads'))
        
    history = UploadedLog.query.order_by(UploadedLog.upload_time.desc()).all()
    return render_template('uploads.html', uploads=history)


def _build_filtered_events_query(args):
    """Builds the security events query based on request parameters."""
    query = SecurityEvent.query
    
    # Advanced filters
    username = args.get('username', '').strip()
    source_ip = args.get('source_ip', '').strip()
    severity = args.get('severity', '').strip()
    event_type = args.get('event_type', '').strip()
    start_date_str = args.get('start_date', '').strip()
    end_date_str = args.get('end_date', '').strip()
    
    if username:
        query = query.filter(SecurityEvent.username.ilike(f'%{username}%'))
    if source_ip:
        query = query.filter(SecurityEvent.source_ip.ilike(f'%{source_ip}%'))
    if severity and severity != 'ALL':
        query = query.filter(SecurityEvent.severity == severity)
    if event_type and event_type != 'ALL':
        query = query.filter(SecurityEvent.event_type == event_type)
        
    # Date Range filtering
    if start_date_str:
        try:
            start_date = datetime.datetime.strptime(start_date_str, '%Y-%m-%d')
            query = query.filter(SecurityEvent.timestamp >= start_date)
        except ValueError:
            pass
            
    if end_date_str:
        try:
            end_date = datetime.datetime.strptime(end_date_str, '%Y-%m-%d')
            # include entire end day up to 23:59:59
            end_date = end_date.replace(hour=23, minute=59, second=59)
            query = query.filter(SecurityEvent.timestamp <= end_date)
        except ValueError:
            pass
            
    return query

@main_bp.route('/events')
@login_required
def events():
    # Construct filters for display
    query = _build_filtered_events_query(request.args)
    
    # Order by timestamp descending
    filtered_events = query.order_by(SecurityEvent.timestamp.desc()).all()
    
    # Extract unique usernames and event types to assist autocomplete / dropdown options in templates
    event_types = db.session.query(SecurityEvent.event_type).distinct().all()
    event_types = [et[0] for et in event_types if et[0]]
    
    return render_template(
        'events.html',
        events=filtered_events,
        event_types=event_types,
        filters=request.args
    )

@main_bp.route('/events/export')
@login_required
def export_csv():
    # Construct filter query
    query = _build_filtered_events_query(request.args)
    filtered_events = query.order_by(SecurityEvent.timestamp.desc()).all()
    
    # Generate CSV in memory
    dest = io.StringIO()
    writer = csv.writer(dest)
    
    # Headers
    writer.writerow([
        'ID', 'Timestamp', 'Event Type', 'Status', 'Source IP', 
        'Username', 'Severity', 'MITRE Technique', 'MITRE Tactic', 
        'Country', 'City', 'Message'
    ])
    
    for event in filtered_events:
        writer.writerow([
            event.id,
            event.timestamp.strftime('%Y-%m-%d %H:%M:%S') if event.timestamp else '',
            event.event_type,
            event.status,
            event.source_ip,
            event.username or '',
            event.severity,
            event.mitre_technique or '',
            event.mitre_tactic or '',
            event.country or '',
            event.city or '',
            event.message or ''
        ])
        
    output = make_response_csv(dest.getvalue())
    return output

def make_response_csv(csv_data):
    response = Response(csv_data, mimetype='text/csv')
    timestamp = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    response.headers['Content-Disposition'] = f'attachment; filename=soc_sentinel_events_{timestamp}.csv'
    return response

@main_bp.route('/uploads/delete/<int:log_id>', methods=['POST'])
@login_required
def delete_log(log_id):
    """Deprovision log uploads and associated security events."""
    uploaded_log = UploadedLog.query.get_or_404(log_id)
    try:
        db.session.delete(uploaded_log)
        db.session.commit()
        flash(f'Log upload history and related events deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting log entry: {str(e)}', 'danger')
        
    return redirect(url_for('main.uploads'))
