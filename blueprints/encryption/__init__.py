from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import os.path


#def encrypt_message(message):
    # Generate a random 128 bits (16 bytes) long key to be used for encryption/decryption
#    key = get_random_bytes(16)
    # Create an AES object
#    cipher_aes = AES.new(key, AES.MODE_EAX)
    # Encrypt
    # Will return the encrypted message and the MAC tag (hash value) of the message
#    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))

#    return key, ciphertext, cipher_aes.nonce, tag


#def decrypt_message(key, ciphertext, nonce, tag):
#    # Create an AES object
#    cipher_aes = AES.new(key, AES.MODE_EAX, nonce)
#    # Decrypt the message
#    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

#   return decrypted_data.decode('utf-8')


def generate_rsa(key_name, key_size=2048):
    rsa_key = RSA.generate(key_size)

    #Make the private key local file
    private_key = rsa_key.export_key()
    with open(f'./keys/{key_name}_pem','wb') as out_file:
        out_file.write(private_key)

    public_key = rsa_key.export_key()
    with open(f'./keys/{key_name}_public.pem','wb') as out_file:
        out_file.write(public_key)


def rsa_encrypt():
    pass


def rsa_decrypt():
    pass
