import os
from flask import Flask, session, g
from config import Config
from app.database import db
from app.models.user import User

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize DB
    db.init_app(app)
    
    # Ensure tables are created
    with app.app_context():
        from app.models import user, uploaded_log, security_event, alert, ioc, setting, incident, incident_note, audit_log, report
        db.create_all()


    
    # Ensure upload folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # User session handler
    @app.before_request
    def load_logged_in_user():
        user_id = session.get('user_id')
        if user_id is None:
            g.user = None
        else:
            g.user = User.query.get(user_id)
            
    # Register blueprints
    from app.blueprints.auth import auth_bp
    from app.blueprints.dashboard import dashboard_bp
    from app.blueprints.main import main_bp
    from app.blueprints.admin import admin_bp
    from app.blueprints.alerts import alerts_bp
    from app.blueprints.iocs import iocs_bp
    from app.blueprints.incidents import incidents_bp
    from app.blueprints.reports import reports_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(iocs_bp)
    app.register_blueprint(incidents_bp)
    app.register_blueprint(reports_bp)

    
    # Custom template filter for humanizing bytes sizes
    @app.template_filter('filesizeformat')
    def filesizeformat(value):
        try:
            bytes_val = float(value)
        except (ValueError, TypeError):
            return "0 Bytes"
            
        if bytes_val < 1024:
            return f"{bytes_val:.0f} Bytes"
        elif bytes_val < 1024 * 1024:
            return f"{bytes_val/1024:.1f} KB"
        else:
            return f"{bytes_val/(1024*1024):.1f} MB"
            
    return app
