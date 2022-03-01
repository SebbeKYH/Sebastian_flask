from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP


def encrypt_message(message):
    # Generate a random 128 bits (16 bytes) long key to be used for encryption/decryption
    key = get_random_bytes(16)
    # Create an AES object
    cipher_aes = AES.new(key, AES.MODE_EAX)
    # Encrypt
    # Will return the encrypted message and the MAC tag (hash value) of the message
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))

    return key, ciphertext, cipher_aes.nonce, tag


#def decrypt_message(key, ciphertext, nonce, tag):
#    # Create an AES object
#    cipher_aes = AES.new(key, AES.MODE_EAX, nonce)
#    # Decrypt the message
#    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return decrypted_data.decode('utf-8')


def generate_rsa():
    pass


def rsa_encrypt():
    pass


def rsa_decrypt():
    pass
