import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# RUNNING THIS SCRIPT WILL ROTATE THE PRIVATE KEY!!!
# DONT DO IT!!
import settings


def write_key():
    key = Fernet.generate_key()
    with open(settings.auth_app_shared_key, 'wb') as key_f:
        key_f.write(key)

def load_key():
    return open(settings.auth_app_shared_key, 'rb').read()

def aes256_cbc_encrypt(msg: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_msg = padder.update(msg) + padder.finalize()

    c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    e = c.encryptor()

    x = e.update(padded_msg) + e.finalize()

    return iv + x

def aes256_cbc_decrypt(x_with_iv: bytes, key: bytes) -> bytes:
    iv = x_with_iv[:16]
    x = x_with_iv[16:]

    c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    d = c.decryptor()

    padded_msg = d.update(x) + d.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_msg) + unpadder.finalize()

if __name__ == '__main__':
    write_key()