
from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import current_user

from controllers.message_controller import get_user_messages
from controllers.user_controller import get_all_but_current_user


bp_admin = Blueprint('bp_admin', __name__)


@bp_admin.before_request
def before_request():
    if not current_user.is_authenticated or not current_user.admin:
        flash('You are not the admin. You cant use the admin page.')
        return redirect(url_for('bp_open.index'))


@bp_admin.get('/admin')
def admin_get():
    messages = get_user_messages()
    users = get_all_but_current_user()
    return render_template('admin.html', users=users, messages=messages)


@bp_admin.get('/admin/<user_id>')
def delete_get(user_id):
    from models import User
    delete_user = User.query.filter(User.id==user_id).delete()
    from app import db
    db.session.commit()
    flash('User successfully deleted!')
    return redirect(url_for('bp_admin.admin_get'))




