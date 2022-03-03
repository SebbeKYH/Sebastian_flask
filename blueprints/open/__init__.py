from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user


from models import User
from passlib.hash import argon2

# Create a blueprint object that can be used as an app object for this blueprint
bp_open = Blueprint('bp_open', __name__)


@bp_open.get('/')
def index():
    return render_template("index.html")


@bp_open.get('/login')
def login_get():
    return render_template('login.html')


@bp_open.post('/login')
def login_post():
    email = request.form['email']
    password = request.form['password']
    user = User.query.filter_by(email=email).first()
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


@bp_open.get('/signup')
def signup_get():
    return render_template('signup.html')


@bp_open.post('/signup')
def signup_post():
    name = request.form['name']
    email = request.form.get('email')
    password = request.form['password']
    hashed_password = argon2.using(rounds=10).hash(password)
    user = User.query.filter_by(email=email).first()  # First will give us an object if user exist, or None if not
    if user:
        # If user is not none, then a user with this email exists in the database
        flash("Email address is already in use")
        return redirect(url_for('bp_open.signup_get'))

    new_user = User(name=name, email=email, password=hashed_password)
    # Trying to generate keys here...
    #Encryption....
    from blueprints import encryption
    # Call function to create key-pairs
    encryption.generate_rsa(key_name=name,key_size=2048)
    #TODO trying to export public key to database for specific user...
    pub_key = RSA.importKey(open(f'./keys/{name}_public.pem').read())
    new_pub_key = User(rsa_key_pub=pub_key)
    fulltext_rsa = PKCS1_OAEP.new(new_pub_key)
    real_fulltext_rsa = fulltext_rsa.encrypt(message=new_pub_key)
    # Check if user with this password exists in the database
    from app import db
    db.session.add(new_user)
    db.session.add(real_fulltext_rsa)
    db.session.commit()


    return redirect(url_for('bp_open.login_get'))
