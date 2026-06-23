from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.models.user import User
from app.database import db
from app.utils.audit import log_audit_event

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard.index'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            log_audit_event('Login', f"User '{username}' authenticated successfully.")
            flash(f'Authentication successful. Welcome, {user.username}.', 'success')
            return redirect(url_for('dashboard.index'))
        else:
            log_audit_event('Login', f"Failed login attempt for user '{username}'.")
            flash('Invalid username or password.', 'danger')
            
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    log_audit_event('Logout', f"User '{username}' logged out.")
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('auth.login'))
