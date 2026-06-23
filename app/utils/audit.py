from flask import session, request, g
from app.database import db
from app.models.audit_log import AuditLog

def log_audit_event(action_type, details):
    """
    Logs an audit event to the database.
    Attempts to retrieve the current user and client IP dynamically.
    """
    user_id = session.get('user_id')
    username = session.get('username')
    
    if not user_id and hasattr(g, 'user') and g.user:
        user_id = g.user.id
        username = g.user.username
        
    # Extract remote IP (taking proxies into account)
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip_address and ',' in ip_address:
        ip_address = ip_address.split(',')[0].strip()
        
    try:
        log_entry = AuditLog(
            user_id=user_id,
            username=username or 'System',
            action_type=action_type,
            details=details,
            ip_address=ip_address
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        # Log to stderr/stdout in development
        print(f"WARNING: Failed to commit audit log. Error: {str(e)}")
