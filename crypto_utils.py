import base64

from OpenSSL import crypto
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

import file_utils as files


def encrypt(plaintext, key):
    fernet = Fernet(key)
    return fernet.encrypt(bytes(plaintext, 'utf-8'))


def decrypt(ciphertext, key):
    fernet = Fernet(key)
    return fernet.decrypt(bytes(ciphertext, 'utf-8'))


def create_signature(content, key):
    return key.sign(content, padding.PKCS1v15(), hashes.SHA256())


def check_signature(content, signature, key):
    try:
        key.verify(base64.b64decode(signature), bytes(content, 'utf-8'), padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        print('Invalid signature')
        return False


def generate_private_key(location):
    private_key = rsa.generate_private_key(65537, 2048, default_backend())
    pem = private_key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption())

    files.save_file(location, pem)
    return private_key


def generate_public_key(private_key, location):
    public_key = private_key.public_key()
    pem = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    files.save_file(location, pem)


def create_keys(private_key_location, public_key_location):
    if files.is_file(private_key_location) and files.is_file(public_key_location):
        return

    private_key = generate_private_key(private_key_location)
    generate_public_key(private_key, public_key_location)


def create_certificates(private_key, ca_cert_location, server_cert_location):
    if files.is_file(ca_cert_location) and files.is_file(server_cert_location):
        return

    cert = crypto.X509()
    cert.get_subject().C = 'HR'
    cert.get_subject().ST = 'Croatia'
    cert.get_subject().L = 'Zagreb'
    cert.get_subject().OU = 'chat app'
    cert.get_subject().CN = 'server.com'
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(60 * 60 * 24)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(private_key)
    cert.sign(private_key, 'sha256')

    files.save_file(server_cert_location, crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    files.save_file(ca_cert_location, crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
