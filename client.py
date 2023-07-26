import base64
import tkinter as tk
from threading import Thread

import simplejson as json
from OpenSSL import SSL
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

import com_utils as communication
import crypto_utils as crypt
import file_utils as files
from constants import *
from ui_utils import create_ui


def verify_cert(conn, cert, errno, depth, result):
    # todo
    return True


def receive():
    while True:
        try:
            data = communication.receive(CONNECTION, SYMMETRIC_KEY)

            if not crypt.check_signature(data['message'], data['signature'], SERVER_PUBLIC_KEY):
                break

            msg_list.insert(tk.END, 'Server: ' + data['message'])
        except SSL.SysCallError:
            print('Connection closed')
            break
        except OSError:
            break


def send(event=None):
    text = msg.get()
    if text == '<quit>':
        CONNECTION.close()
        window.quit()
        return

    communication.send(CONNECTION, text, PRIVATE_KEY, SYMMETRIC_KEY)
    msg_list.insert(tk.END, 'You: ' + text)
    msg.set('')


window, msg, msg_list = create_ui('PyChat Client', send)

if __name__ == '__main__':
    # readme Create private/public keys if non existent else load private key from file
    crypt.create_keys(CLIENT_PRIVATE, CLIENT_PUBLIC)
    PRIVATE_KEY = serialization.load_pem_private_key(files.read_file(CLIENT_PRIVATE), None, default_backend())

    # readme "Connect" to server, "download" and check server cert, create SSL connection
    ctx = SSL.Context(SSL.TLSv1_2_METHOD)
    ctx.set_verify(SSL.VERIFY_PEER, verify_cert)

    CONNECTION = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    CONNECTION.connect(ADDRESS)

    # readme Generate symmetric key, encrypt it with server public key, and send it to server
    SERVER_PUBLIC_KEY = serialization.load_pem_public_key(files.read_file(SERVER_PUBLIC), default_backend())
    SYMMETRIC_KEY = Fernet.generate_key()
    secret = SERVER_PUBLIC_KEY.encrypt(SYMMETRIC_KEY, padding.PKCS1v15())

    signature = crypt.create_signature(secret, PRIVATE_KEY)
    message = {'message': base64.b64encode(secret), 'signature': base64.b64encode(signature)}
    CONNECTION.send(bytes(json.dumps(message), 'utf-8'))

    # readme Communication with symmetric key encryption and public key signature
    receive_thread = Thread(target=receive)
    receive_thread.start()

    tk.mainloop()
