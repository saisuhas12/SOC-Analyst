import os
import datetime
import json
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app, send_file
from app.database import db
from app.models.report import Report
from app.models.alert import Alert
from app.models.ioc import IOCIndicator, IOCMatch
from app.models.incident import Incident
from app.models.user import User
from app.utils.decorators import role_required, login_required
from app.utils.audit import log_audit_event
from app.services.pdf_generator import PDFReportGenerator

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/reports')
@login_required
@role_required('admin', 'analyst', 'viewer')
def index():
    all_reports = Report.query.order_by(Report.created_at.desc()).all()
    all_incidents = Incident.query.order_by(Incident.created_at.desc()).all()
    
    return render_template('reports.html', reports=all_reports, incidents=all_incidents)

@reports_bp.route('/reports/prefill-data')
@login_required
@role_required('admin', 'analyst')
def prefill_data():
    """API endpoint to get pre-populated draft content based on the selected report type."""
    report_type = request.args.get('report_type', '')
    incident_id_str = request.args.get('incident_id', '')
    
    now = datetime.datetime.utcnow()
    last_24h = now - datetime.timedelta(hours=24)
    
    title = f"{report_type} - {now.strftime('%Y-%m-%d')}"
    exec_summary = ""
    findings = ""
    recs = ""
    charts_data = {}
    
    if report_type == 'Daily SOC Report':
        # Compile 24h metrics
        alerts_24h = Alert.query.filter(Alert.created_at >= last_24h).all()
        count = len(alerts_24h)
        
        sevs = {'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0}
        types = {}
        for a in alerts_24h:
            sevs[a.severity] = sevs.get(a.severity, 0) + 1
            types[a.alert_type] = types.get(a.alert_type, 0) + 1
            
        exec_summary = (
            f"During the last 24-hour cycle (since {last_24h.strftime('%Y-%m-%d %H:%M UTC')}), "
            f"SOC Sentinel XDR analyzed security logs and escalated a total of {count} alerts.\n\n"
            f"Severity breakdown: {sevs['Critical']} Critical, {sevs['High']} High, {sevs['Medium']} Medium, and {sevs['Low']} Low.\n"
            f"Resolution rate has remained stable. Standard containment actions were successfully initiated."
        )
        
        types_summary = ", ".join([f"{k} ({v})" for k, v in types.items()]) if types else "None"
        findings = (
            f"A total of {count} alerts were verified. The dominant alert type(s) were: {types_summary}.\n\n"
            "Key Indicators:\n"
            "- Internal hosts were scanned from external IP addresses.\n"
            "- Authentication failures peaked during non-business hours.\n"
            "- No signs of widespread data exfiltration were detected."
        )
        
        recs = (
            "1. Enforce multi-factor authentication (MFA) for users experiencing suspicious login patterns.\n"
            "2. Update firewall egress filters to block top repetitive attacking external source IPs.\n"
            "3. Schedule credentials rotate for system administrator service accounts."
        )
        
        # Populate charts
        charts_data = {
            'severity': {
                'labels': list(sevs.keys()),
                'counts': list(sevs.values())
            },
            'types': {
                'labels': list(types.keys()),
                'counts': list(types.values())
            }
        }
        
    elif report_type == 'Threat Summary Report':
        # Compile global metrics
        total_alerts = Alert.query.count()
        critical_alerts = Alert.query.filter_by(severity='Critical').count()
        high_alerts = Alert.query.filter_by(severity='High').count()
        
        # Top IPs
        top_ips_query = db.session.query(
            Alert.source_ip, db.func.count(Alert.id)
        ).filter(Alert.source_ip != None, Alert.source_ip != '0.0.0.0').group_by(Alert.source_ip).order_by(db.func.count(Alert.id).desc()).limit(5).all()
        
        ips_str = ", ".join([f"{ip} ({count} alerts)" for ip, count in top_ips_query]) if top_ips_query else "None"
        
        exec_summary = (
            f"This Threat Summary Report reviews the complete lifecycle of alert escalations in SOC Sentinel XDR.\n"
            f"To date, the system has logged {total_alerts} security alerts, with {critical_alerts} Critical and {high_alerts} High threats.\n\n"
            "This report highlights exposure on external-facing interfaces and charts key attack vectors."
        )
        
        findings = (
            f"Persistent brute force attacks represent the highest threat vector.\n"
            f"The top attacking external IP addresses are: {ips_str}.\n\n"
            "Analysis shows attackers are targeting weak credential systems and known exposed protocols."
        )
        
        recs = (
            "1. Deploy automated IP blocking/shunning for sources with more than 10 failed login attempts.\n"
            "2. Perform configuration audits on systems displaying repeating credential guessing attempts.\n"
            "3. Cross-reference threat intelligence feeds to identify potential command-and-control (C2) domains."
        )
        
        # Charts data
        severity_counts = {'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0}
        all_sevs = db.session.query(Alert.severity, db.func.count(Alert.id)).group_by(Alert.severity).all()
        for s, c in all_sevs:
            if s in severity_counts:
                severity_counts[s] = c
                
        ip_labels = [ip for ip, c in top_ips_query]
        ip_counts = [c for ip, c in top_ips_query]
        
        charts_data = {
            'severity': {
                'labels': list(severity_counts.keys()),
                'counts': list(severity_counts.values())
            },
            'ips': {
                'labels': ip_labels,
                'counts': ip_counts
            }
        }
        
    elif report_type == 'IOC Match Report':
        # Compile IOC Match metrics
        total_iocs = IOCIndicator.query.count()
        matches_count = IOCMatch.query.count()
        
        # Let's count by IOC types
        match_types = db.session.query(
            IOCIndicator.ioc_type, db.func.count(IOCMatch.id)
        ).join(IOCMatch, IOCIndicator.id == IOCMatch.ioc_indicator_id).group_by(IOCIndicator.ioc_type).all()
        
        ioc_summary = ", ".join([f"{t} ({c} matches)" for t, c in match_types]) if match_types else "None"
        
        exec_summary = (
            f"Threat Intelligence Feed matching summary. The local threat database holds {total_iocs} indicators.\n"
            f"We have registered {matches_count} matching occurrences between external threat data feeds and local system audit logs."
        )
        
        findings = (
            f"IOC Matches breakdown: {ioc_summary}.\n\n"
            "High-confidence threat matches indicate active beacons to known malicious command-and-control servers or execution of cataloged payloads."
        )
        
        recs = (
            "1. Isolate endpoints immediately showing communication to confirmed C2 domains.\n"
            "2. Implement automated block rules on firewalls for IPs flagged as Critical indicators.\n"
            "3. Clear local cache and execute deep AV sweeps on endpoints interacting with malicious domains."
        )
        
        # Charts
        type_labels = [t for t, c in match_types]
        type_counts = [c for t, c in match_types]
        charts_data = {
            'types': {
                'labels': type_labels,
                'counts': type_counts
            }
        }
        
    elif report_type == 'Incident Investigation Report':
        # Detail of a single incident
        if incident_id_str:
            incident = Incident.query.get(int(incident_id_str))
            if incident:
                title = f"Incident Investigation Report: #{incident.id} - {incident.title}"
                assigned = incident.assigned_user.username if incident.assigned_user else 'Unassigned'
                
                exec_summary = (
                    f"Investigation report for Incident #{incident.id}: '{incident.title}'.\n"
                    f"Incident status is currently '{incident.status}' and assessed at '{incident.severity}' severity.\n"
                    f"Assigned Analyst: {assigned}.\n\n"
                    f"Description: {incident.description or 'No description provided.'}"
                )
                
                # Fetch timeline as text
                timeline_lines = []
                for event in incident.timeline:
                    # format timestamp
                    ts_str = event.get('timestamp', '')
                    if ts_str:
                        try:
                            ts = datetime.datetime.fromisoformat(ts_str)
                            ts_str = ts.strftime('%Y-%m-%d %H:%M')
                        except ValueError:
                            pass
                    timeline_lines.append(f"- [{ts_str}] ({event.get('user', 'System')}) {event.get('message')}")
                timeline_text = "\n".join(timeline_lines) if timeline_lines else "No timeline events recorded."
                
                # Fetch notes
                notes_lines = []
                notes = IncidentNote.query.filter_by(incident_id=incident.id).order_by(IncidentNote.created_at.asc()).all()
                for note in notes:
                    ts_str = note.created_at.strftime('%Y-%m-%d %H:%M') if note.created_at else ''
                    notes_lines.append(f"[{ts_str}] {note.author.username if note.author else 'Unknown'}:\n{note.note_text}")
                notes_text = "\n\n".join(notes_lines) if notes_lines else "No notes added."
                
                findings = (
                    f"--- INCIDENT TIMELINE ---\n{timeline_text}\n\n"
                    f"--- ANALYST INVESTIGATION NOTES ---\n{notes_text}"
                )
                
                recs = (
                    "1. Formulate security posture updates if the root cause was verified as configuration error.\n"
                    "2. Mark associated logs and system templates for future anomaly modeling.\n"
                    "3. Close the incident once post-incident validation checks pass."
                )
            else:
                exec_summary = "Incident not found."
        else:
            exec_summary = "Select an active incident from the dropdown to run investigation summary."
            
    return {
        'title': title,
        'executive_summary': exec_summary,
        'findings': findings,
        'recommendations': recs,
        'charts_data': charts_data
    }

@reports_bp.route('/reports/generate', methods=['POST'])
@login_required
@role_required('admin', 'analyst')
def generate():
    report_type = request.form.get('report_type', '').strip()
    title = request.form.get('title', '').strip()
    executive_summary = request.form.get('executive_summary', '').strip()
    findings = request.form.get('findings', '').strip()
    recommendations = request.form.get('recommendations', '').strip()
    charts_data_str = request.form.get('charts_data', '{}').strip()
    
    if not report_type or not title:
        flash('Report Type and Title are required.', 'danger')
        return redirect(url_for('reports.index'))
        
    try:
        charts_data = json.loads(charts_data_str or '{}')
    except Exception:
        charts_data = {}
        
    # Create the report record
    report = Report(
        report_type=report_type,
        title=title,
        created_by_id=session.get('user_id'),
        executive_summary=executive_summary,
        findings=findings,
        recommendations=recommendations,
        charts_data=charts_data,
        pdf_path="temp"  # Will update immediately after saving file
    )
    
    db.session.add(report)
    db.session.flush() # get report.id
    
    # Save the physical PDF file
    reports_dir = os.path.join(current_app.static_folder, 'uploads', 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    
    filename = f"report_{report.id}_{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}.pdf"
    pdf_file_path = os.path.join(reports_dir, filename)
    
    try:
        # Generate the PDF file
        PDFReportGenerator.generate(report, pdf_file_path)
        
        # Update path
        report.pdf_path = f"uploads/reports/{filename}"
        db.session.commit()
        
        log_audit_event('User Action', f"Generated {report.report_type} PDF: '{report.title}'")
        flash(f"Successfully generated {report.report_type}.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error compiling PDF document: {str(e)}", "danger")
        
    return redirect(url_for('reports.index'))

@reports_bp.route('/reports/download/<int:report_id>')
@login_required
@role_required('admin', 'analyst', 'viewer')
def download(report_id):
    report = Report.query.get_or_404(report_id)
    pdf_path = os.path.join(current_app.static_folder, report.pdf_path)
    
    if not os.path.exists(pdf_path):
        flash("PDF file not found on server disk.", "danger")
        return redirect(url_for('reports.index'))
        
    # Serve file download
    return send_file(pdf_path, as_attachment=True, download_name=os.path.basename(pdf_path))
