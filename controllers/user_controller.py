from flask_login import current_user


def get_all_but_current_user():
    from models import User
    user = current_user
    return User.query.filter(User.id != user.id).all()


def get_all_users():
    from models import User
    return User.query.all()


def get_user_by_id(user_id):
    from models import User
    return User.query.filter(User.id == user_id).first()

# TODO Will this work? NO it wont
def create_admin_contact():
    from app import db
    db.session.add(admin_contact=1)
# Telling database to add number one in admin contact