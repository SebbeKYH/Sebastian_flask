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


def get_user_messages():
    return current_user.recv_messages


def get_unread_msg_count():
    user = current_user
    msg_count = 0
    for msg in user.recv_messages:
        if not msg.read:
            msg_count += 1
    return msg_count


def get_key_by_id(message_aes_key):
    from models import Message
    return Message.query.filter(Message.aes_key == message_aes_key).first()


def rsa_encrypt(rsa_key_name, key):
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

# TODO I NEED THIS ONE
#def rsa_decrypt(cipher, private_key):
#    if type(private_key) != RsaKey:
#        if os.path.isfile(f'./keys/{private_key}_private.pem'):
#            private_key = RSA.importKey(open(f'./keys/{private_key}_private.pem').read())
#        else:
#            print(f'No key file named {private_key}_private.pem found')
#            return ""
#    cipher_rsa = PKCS1_OAEP.new(private_key)
#    return cipher_rsa.decrypt(cipher)


#TODO I NEED THIS ONE
#def decrypt_message(priv_key_name, message_aes_key):
#    aes_key = rsa_decrypt(encrypted_aes_key, priv_key_name)
#    plaintext = aes_decrypt(aes_key, aes_cipher, aes_nonce, aes_tag)
#    return plaintext

    # return cipher_rsa.decrypt(cipher).decode('utf-8')
#TODO I NEED THIS ONE
#def aes_decrypt(aes_key, ciphertext, nonce, tag):
    # Create an AES object
#    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    # Decrypt the message
#    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

#    return decrypted_data.decode('utf-8')



# def aes_key():
#    key = get_random_bytes(16)
#    cipher_key_aes = AES.new(key, AES.MODE_EAX)
#    return cipher_key_aes

# def encrypt(reciever_email, message):
#    key = get_random_bytes(16)
#    cipher_aes = AES.new(key, AES.MODE_EAX)
#    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))

#    recipient_key = RSA.importKey(open(f'./keys/{reciever_email}_public.pem').read())
#    cipher_rsa = PKCS1_OAEP.new(recipient_key)
#    rsa_aes_combo = cipher_rsa.encrypt(key)

#    return rsa_aes_combo
# return key, ciphertext, cipher_aes.nonce, tag


# def rsa_encrypt(key_name, key):
#    return cipher_rsa.encrypt(key)
