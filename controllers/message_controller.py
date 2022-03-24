from flask_login import current_user
from controllers.user_controller import get_user_by_id, get_user_by_email
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import base64

def create_message(title, body, receiver_id):
    from models import Message
    # User is the current logged in user
    user = current_user
    # Message will contain title body and sender_id
    message = Message(aes_key=rsa_aes_combo, body=body, sender_id=user.id)
    receiver_id = int(receiver_id)
    receiver = get_user_by_id(receiver_id)
    message.receivers.append(receiver)
    # body of message will be aes encrypted...
    combo = encrypt(message=body, reciever_email=receiver.email)
    print()

    #recipient_rsa_key_name = get_user_by_email(user_email=User.email)



    #encoded = base64.b64encode(encrypted_aes_key, 'utf-8')
    from app import db

    db.session.add(message)
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

def encrypt(reciever_email, message):
    key = get_random_bytes(16)
    cipher_aes = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))

    recipient_key = RSA.importKey(open(f'./keys/{reciever_email}_public.pem').read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    rsa_aes_combo = cipher_rsa.encrypt(key)

    return rsa_aes_combo
    #return key, ciphertext, cipher_aes.nonce, tag


#def rsa_encrypt(key_name, key):
#    return cipher_rsa.encrypt(key)
