import base64
import tkinter as tk
from threading import Thread

import simplejson as json
from OpenSSL import crypto, SSL
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import com_utils as communication
import crypto_utils as crypt
import file_utils as files
from constants import *
from ui_utils import create_ui


def broadcast(event=None):
    text = msg.get()
    communication.send(CLIENT, text, PRIVATE_KEY, SYMMETRIC_KEY)
    msg_list.insert(tk.END, 'You: ' + text)
    msg.set('')


def get_client_name(client, key):
    communication.send(client, 'Type your name and press enter!', PRIVATE_KEY, key)
    try:
        message = communication.receive(client, key)
        if crypt.check_signature(message['message'], message['signature'], CLIENT_PUBLIC_KEY):
            return message['message']
    except SSL.SysCallError:
        print('Connection closed')

    client.close()
    window.quit()


def handle_client(client, key):
    name = get_client_name(client, key)
    communication.send(client, f'Welcome {name}! Type <quit> to leave the chat.', PRIVATE_KEY, key)
    msg_list.insert(tk.END, f'{name} has joined the chat!')

    while True:
        try:
            message = communication.receive(client, key)
            if crypt.check_signature(message['message'], message['signature'], CLIENT_PUBLIC_KEY):
                msg_list.insert(tk.END, 'Client: ' + message['message'])
        except SSL.SysCallError:
            print('Connection closed')
            break
        except OSError:
            break

    msg_list.insert(tk.END, f'{name} has left the chat.')
    client.close()
    window.quit()


def check_signature(data, signature):
    try:
        CLIENT_PUBLIC_KEY.verify(base64.b64decode(signature),
                                 base64.b64decode(data),
                                 padding.PKCS1v15(),
                                 hashes.SHA256())
        return True
    except InvalidSignature:
        CLIENT.close()
        print('Invalid signature')
        return False


window, msg, msg_list = create_ui('PyChat Server', broadcast)

if __name__ == '__main__':
    # readme Create private/public keys if non existent else load private key from file
    crypt.create_keys(SERVER_PRIVATE, SERVER_PUBLIC)
    PRIVATE_KEY = serialization.load_pem_private_key(files.read_file(SERVER_PRIVATE), None, default_backend())
    # readme Create certificates if not created
    private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, files.read_file(SERVER_PRIVATE))
    crypt.create_certificates(private_key, CA_CERT, SERVER_CERT)

    # readme Start SSL server and accept connections
    ctx = SSL.Context(SSL.TLSv1_2_METHOD)
    ctx.set_options(SSL.OP_NO_SSLv2)
    ctx.use_privatekey_file(SERVER_PRIVATE)
    ctx.use_certificate_file(SERVER_CERT)
    ctx.load_verify_locations(CA_CERT)

    SERVER = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    SERVER.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    SERVER.bind(ADDRESS)
    SERVER.listen(1)

    print('Waiting for client connections...')
    CLIENT, client_address = SERVER.accept()
    print(f'Client on {client_address} has joined the chat.')
    CLIENT_PUBLIC_KEY = serialization.load_pem_public_key(files.read_file(CLIENT_PUBLIC), default_backend())

    # readme Receive symmetric key from client
    data = json.loads(CLIENT.recv(BUFFER_SIZE).decode('utf8'))
    if check_signature(data['message'], data['signature']):
        SYMMETRIC_KEY = PRIVATE_KEY.decrypt(base64.b64decode(data['message']), padding.PKCS1v15())
        Thread(target=handle_client, args=(CLIENT, SYMMETRIC_KEY)).start()
        tk.mainloop()

    SERVER.close()
