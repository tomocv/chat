import base64

import simplejson as json

import crypto_utils as crypto
from constants import BUFFER_SIZE


def create_message(text, pkey, key):
    signature = crypto.create_signature(bytes(text, 'utf-8'), pkey)
    message = {'message': text, 'signature': base64.b64encode(signature)}
    return crypto.encrypt(json.dumps(message), key)


def send(client, data, pkey, key):
    message = create_message(data, pkey, key)
    client.send(message)


def receive(client, key):
    data = client.recv(BUFFER_SIZE).decode('utf8')
    message = crypto.decrypt(data, key)
    return json.loads(message)
