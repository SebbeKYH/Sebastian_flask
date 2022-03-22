from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, current_user

from controllers.user_controller import get_user_by_id, generate_rsa
from models import User
from passlib.hash import argon2

# Create a blueprint object that can be used as an app object for this blueprint
bp_open = Blueprint('bp_open', __name__)


#Route for homepage
@bp_open.get('/')
def index():
    return render_template("index.html")


#Route for login-page
@bp_open.get('/login')
def login_get():
    return render_template('login.html')


# Handles input via login-page to send to database
@bp_open.post('/login')
def login_post():
    # Input information is fetched...
    email = request.form['email']
    password = request.form['password']
    user = User.query.filter_by(email=email).first()
    # If mail or password is wrong a message appears...
    if user is None:
        flash('Wrong email or password')
        return redirect(url_for('bp_open.login_get'))
    if not argon2.verify(password, user.password):
        flash('Wrong email or password')
        return redirect(url_for('bp_open.login_get'))

    # User is verified. Login in user!
    login_user(user)
    user.online = True

    from app import db
    db.session.commit()
    return redirect(url_for('bp_user.user_get'))


# Route for sing-up page...
@bp_open.get('/signup')
def signup_get():
    return render_template('signup.html')


# Request information from signup page to create new user
@bp_open.post('/signup')
def signup_post():
    name = request.form['name']
    email = request.form.get('email')
    password = request.form['password']
    hashed_password = argon2.using(rounds=10).hash(password)
    user = User.query.filter_by(email=email).first()  # First will give us an object if user exist, or None if not
    #Encryption....
    public_key=generate_rsa(key_name=name)
    if user:
        # If user is not none, then a user with this email exists in the database
        flash("Email address is already in use")
        return redirect(url_for('bp_open.signup_get'))

    new_user = User(name=name, email=email, password=hashed_password, public_rsa_key=public_key)

    from app import db
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('bp_open.login_get'))

