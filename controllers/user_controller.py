from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
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


def get_user_by_email(user_email):
    from models import User
    # user = current_user
    return User.query.filter(User.email == user_email).first()


def generate_rsa(key_name, key_size=1024):
    # Generate a key-pair with the specified key size
    key = RSA.generate(key_size)

    # Extract the private key
    private_key = key.export_key()
    with open(f'./keys/{key_name}_private.pem', 'wb') as out_file:
        out_file.write(private_key)

    # Extract the public key
    public_key = key.public_key().export_key()
    with open(f'./keys/{key_name}_public.pem', 'wb') as out_file:
        out_file.write(public_key)

    return public_key
