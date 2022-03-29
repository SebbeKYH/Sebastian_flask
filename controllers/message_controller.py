import os

from flask_login import current_user
from controllers.user_controller import get_user_by_id, get_user_by_email, generate_rsa
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP


def create_message(body, receiver_id):
    from models import Message
    user = current_user
    receiver_id = int(receiver_id)
    receiver = get_user_by_id(receiver_id)

    # Encrypt the message and return the message, the key, nonce and tag
    aes_encrypted_message, aes_key, nonce, tag = aes_encrypt_message(body)
    # encrypt the aes key with rsa
    encrypted_key = rsa_encrypt(receiver.email, aes_key)
    message = Message(aes_key=encrypted_key, body=aes_encrypted_message, sender_id=user.id, aes_nonce=nonce, aes_tag=tag)
    message.receivers.append(receiver)

    from app import db
    db.session.add(message)
    db.session.commit()
    return aes_encrypted_message, aes_key, nonce, tag


def get_user_messages():
    return current_user.recv_messages


def get_unread_msg_count():
    user = current_user
    msg_count = 0
    for msg in user.recv_messages:
        if not msg.read:
            msg_count += 1
    return msg_count


def get_aes_message(message_id):
    from models import Message
    database_aes_message = Message.query.filter(message_id==message_id).first()
    aes_message = database_aes_message.body
    return aes_message


def get_aes_key(message_id):
    from models import Message
    database_aes_key = Message.query.filter(message_id==message_id).first()
    aes_key = database_aes_key.aes_key
    return aes_key


def get_aes_nonce(message_id):
    from models import Message
    # KANSKE SKA VARA ALL() HÄR
    database_nonce = Message.query.filter(message_id==message_id).first()
    aes_nonce = database_nonce.aes_nonce
    return aes_nonce


def get_aes_tag(message_id):
    from models import Message
    database_tag = Message.query.filter(message_id==message_id).first()
    aes_tag = database_tag.aes_tag
    return aes_tag


def get_sender_id():
    from models import Message
    database_sender_id = Message.query.filter(Message.sender_id).first()
    aes_sender_id = database_sender_id.sender_id
    return aes_sender_id

def get_rsa_key(message_id):
    from models import User
    database_rsa = User.query.filter(message_id==message_id).first()
    rsa_key = database_rsa.public_rsa_key
    return rsa_key


def rsa_encrypt(rsa_key_name, key):
    #sender_id = get_sender_id()
    #recipient_key = get_rsa_key(sender_id)
    #imported_key = RSA.importKey(recipient_key)

    path_to_file = "C:/Code/NEW_CODE/Comupter_Communication_and_Safety/Joakim projects/first_flask/keys/"
    recipient_key = RSA.importKey(open(f'{path_to_file}{rsa_key_name}_public.pem', 'r').read())

    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_key = cipher_rsa.encrypt(key)
    return encrypted_key


def aes_encrypt_message(message):
    key = get_random_bytes(16)
    cipher_aes = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf8'))
    return ciphertext, key, cipher_aes.nonce, tag


def rsa_decrypt(cipher, private_key):
    if type(private_key) != RsaKey:
        if os.path.isfile(f'./keys/{private_key}_private.pem'):
            private_key = RSA.importKey(open(f'./keys/{private_key}_private.pem').read())
        else:
            print(f'No key file named {private_key}_private.pem found')
            return ""
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(cipher)


def decrypt_message(priv_key_name):

    sender_id = get_sender_id()

    aes_key = get_aes_key(sender_id)
    print(aes_key)

    nonce = get_aes_nonce(sender_id)
    print(nonce)

    tag = get_aes_tag(sender_id)
    print(tag)

    aes_encrypted_message = get_aes_message(sender_id)
    print (aes_encrypted_message)


    aes_encrypted_key = rsa_decrypt(aes_key, priv_key_name)
    plaintext = aes_decrypt(aes_encrypted_key, aes_encrypted_message, nonce, tag)
    return plaintext


def aes_decrypt(aes_key, ciphertext, nonce, tag):
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return decrypted_data.decode('utf-8')


