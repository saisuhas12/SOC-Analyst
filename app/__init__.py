import os
import datetime
from flask import Flask, session, g, jsonify, render_template
from config import Config
from app.database import db
from app.models.user import User
from flask_migrate import Migrate

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize DB & Migration Support
    db.init_app(app)
    Migrate(app, db)
    
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
            
    # Production-Grade Health Check Endpoint
    @app.route('/health')
    def health():
        try:
            # Query the database to verify active connection
            db.session.execute(db.text('SELECT 1'))
            return jsonify({
                'status': 'healthy',
                'database': 'connected',
                'timestamp': datetime.datetime.utcnow().isoformat()
            }), 200
        except Exception as e:
            return jsonify({
                'status': 'unhealthy',
                'database': 'disconnected',
                'error': str(e),
                'timestamp': datetime.datetime.utcnow().isoformat()
            }), 500

    # Production-Grade Error Handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('errors/500.html'), 500
            
    return app
