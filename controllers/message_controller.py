from flask_login import current_user
from blueprints import encryption
from controllers.user_controller import get_user_by_id


def create_message(title, body, receiver_id):
    from models import Message
    user = current_user
    encrypted_body = encryption.encrypt_message(body)
    message = Message(title=title, body=encrypted_body[1], sender_id=user.id)
    receiver_id = int(receiver_id)
    receiver = get_user_by_id(receiver_id)
    message.receivers.append(receiver)
    from app import db
    db.session.add(message)
#    db.session.add(encrypt)
    db.session.commit()


def get_user_messages():
    return current_user.recv_messages


def get_unread_msg_count():
    user = current_user
    msg_count = 0

    for msg in user.recv_messages:
        if not msg.read:
            msg_count += 1

    return msg_count
