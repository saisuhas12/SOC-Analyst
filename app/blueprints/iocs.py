import csv
import io
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.database import db
from app.models.ioc import IOCIndicator, IOCMatch
from app.models.setting import SystemSetting
from app.utils.decorators import login_required

iocs_bp = Blueprint('iocs', __name__)

@iocs_bp.route('/iocs')
@login_required
def index():
    indicators = IOCIndicator.query.order_by(IOCIndicator.created_at.desc()).all()
    matches = IOCMatch.query.order_by(IOCMatch.matched_at.desc()).all()
    
    # Settings
    brute_force_threshold = SystemSetting.get_value('brute_force_threshold', '5')
    
    return render_template(
        'iocs.html',
        indicators=indicators,
        matches=matches,
        brute_force_threshold=brute_force_threshold
    )

@iocs_bp.route('/iocs/create', methods=['POST'])
@login_required
def create_ioc():
    ioc_type = request.form.get('ioc_type', '').strip()
    value = request.form.get('value', '').strip()
    severity = request.form.get('severity', 'Medium').strip()
    description = request.form.get('description', '').strip()
    
    if not ioc_type or not value:
        flash("IOC Type and Value are required.", "danger")
        return redirect(url_for('iocs.index'))
        
    # Check for duplicate
    existing = IOCIndicator.query.filter_by(value=value).first()
    if existing:
        flash(f"Indicator with value '{value}' already exists.", "warning")
        return redirect(url_for('iocs.index'))
        
    try:
        new_ioc = IOCIndicator(
            ioc_type=ioc_type,
            value=value,
            severity=severity,
            description=description,
            created_by_id=session['user_id']
        )
        db.session.add(new_ioc)
        db.session.commit()
        flash(f"Successfully added IOC indicator '{value}'.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error adding indicator: {str(e)}", "danger")
        
    return redirect(url_for('iocs.index'))

@iocs_bp.route('/iocs/upload', methods=['POST'])
@login_required
def upload_iocs():
    if 'file' not in request.files:
        flash("No file part in request.", "danger")
        return redirect(url_for('iocs.index'))
        
    file = request.files['file']
    if file.filename == '':
        flash("No file selected.", "danger")
        return redirect(url_for('iocs.index'))
        
    try:
        content = file.read().decode('utf-8', errors='ignore')
        f = io.StringIO(content)
        reader = csv.DictReader(f)
        
        # Check headers
        headers = reader.fieldnames or []
        required_headers = {'ioc_type', 'value'}
        
        # Check if basic columns exist (case-insensitive checks)
        normalized_headers = {h.lower().replace(' ', '_'): h for h in headers}
        
        added_count = 0
        skipped_count = 0
        
        for row in reader:
            # Map normalized headers
            ioc_type_val = row.get(normalized_headers.get('ioc_type', '')) or row.get('ioc_type')
            val = row.get(normalized_headers.get('value', '')) or row.get('value')
            sev = row.get(normalized_headers.get('severity', '')) or row.get('severity') or 'Medium'
            desc = row.get(normalized_headers.get('description', '')) or row.get('description') or ''
            
            if not ioc_type_val or not val:
                skipped_count += 1
                continue
                
            ioc_type_val = ioc_type_val.strip()
            val = val.strip()
            sev = sev.strip()
            desc = desc.strip()
            
            # Basic validation of type
            valid_types = {'IP Address', 'Domain', 'URL', 'File Hash'}
            # Try to match case-insensitively or clean up type
            matched_type = None
            for vt in valid_types:
                if vt.lower() == ioc_type_val.lower() or vt.replace(' ', '').lower() == ioc_type_val.lower():
                    matched_type = vt
                    break
            
            if not matched_type:
                matched_type = 'Domain' # default fallback
                
            # Check duplicate
            existing = IOCIndicator.query.filter_by(value=val).first()
            if existing:
                # Update existing indicator description / severity
                existing.severity = sev
                existing.description = desc
                existing.ioc_type = matched_type
                skipped_count += 1
            else:
                new_ioc = IOCIndicator(
                    ioc_type=matched_type,
                    value=val,
                    severity=sev,
                    description=desc,
                    created_by_id=session['user_id']
                )
                db.session.add(new_ioc)
                added_count += 1
                
        db.session.commit()
        flash(f"IOC List processed: Ingested {added_count} new indicators, updated/skipped {skipped_count}.", "success")
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error processing IOC file upload: {str(e)}", "danger")
        
    return redirect(url_for('iocs.index'))

@iocs_bp.route('/iocs/delete/<int:ioc_id>', methods=['POST'])
@login_required
def delete_ioc(ioc_id):
    ioc = IOCIndicator.query.get_or_404(ioc_id)
    try:
        db.session.delete(ioc)
        db.session.commit()
        flash(f"Deleted IOC indicator '{ioc.value}'.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting indicator: {str(e)}", "danger")
    return redirect(url_for('iocs.index'))

@iocs_bp.route('/iocs/settings', methods=['POST'])
@login_required
def save_settings():
    threshold_str = request.form.get('brute_force_threshold', '').strip()
    
    if not threshold_str:
        flash("Brute force threshold cannot be empty.", "danger")
        return redirect(url_for('iocs.index'))
        
    try:
        threshold = int(threshold_str)
        if threshold < 1:
            raise ValueError
    except ValueError:
        flash("Threshold must be a positive integer.", "danger")
        return redirect(url_for('iocs.index'))
        
    try:
        SystemSetting.set_value('brute_force_threshold', str(threshold))
        db.session.commit()
        flash("Configuration settings saved successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error saving settings: {str(e)}", "danger")
        
    return redirect(url_for('iocs.index'))
