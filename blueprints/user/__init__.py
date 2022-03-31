from flask import Blueprint, render_template, redirect, url_for, request
from flask_login import logout_user, login_required, current_user

from controllers.message_controller import create_message, get_user_messages, decrypt_message
from controllers.user_controller import get_all_but_current_user, get_user_by_id

bp_user = Blueprint('bp_user', __name__)


@bp_user.get('/profile')
@login_required
def user_get():
    users = get_all_but_current_user()
    return render_template("user.html", users=users)


@bp_user.get('/logout')
def logout_get():
    user = current_user
    user.online = False

    from app import db
    db.session.commit()
    logout_user()
    return redirect(url_for('bp_open.index'))


@bp_user.get('/message/<user_id>')
def message_get(user_id):
    user_id = int(user_id)
    receiver = get_user_by_id(user_id)
    return render_template('message.html', receiver=receiver)


@bp_user.post('/message')
def message_post():
    body = request.form['body']
    receiver_id = request.form['user_id']
    create_message(body, receiver_id)
    return redirect(url_for('bp_user.user_get'))


@bp_user.get('/mailbox')
def mailbox_get():
    list_of_messages = get_user_messages()
    decrypted_message_list = []
    path_to_file = "C:/Code/NEW_CODE/Comupter_Communication_and_Safety/Joakim projects/first_flask/keys/"
    from Crypto.PublicKey import RSA
    rsa_key_name = current_user.email
    priv_key_name = RSA.importKey(open(f'{path_to_file}{rsa_key_name}_private.pem', 'r').read())

    for message in list_of_messages:
        decrypted_message_list.append(decrypt_message(priv_key_name=priv_key_name, id=message.id))

    print()
    return render_template('mailbox.html', messages=list_of_messages, decrypted_message=decrypted_message_list)
