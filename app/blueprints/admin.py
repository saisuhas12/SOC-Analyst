from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.models.user import User
from app.database import db
from app.utils.decorators import admin_required

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/users', methods=['GET', 'POST'])
@admin_required
def users():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'analyst').strip()
        
        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('admin.users'))
            
        # Check duplicate
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already registered.', 'danger')
            return redirect(url_for('admin.users'))
            
        try:
            new_user = User(username=username, email=email, role=role)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash(f'Successfully provisioned user: {username} ({role}).', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {str(e)}', 'danger')
            
        return redirect(url_for('admin.users'))
        
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template('users.html', users=all_users)

@admin_bp.route('/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == session.get('user_id'):
        flash('Cannot deprovision yourself.', 'danger')
        return redirect(url_for('admin.users'))
        
    user = User.query.get_or_404(user_id)
    try:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} has been deprovisioned.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')
        
    return redirect(url_for('admin.users'))
