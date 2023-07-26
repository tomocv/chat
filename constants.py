import socket

HOST = socket.gethostname()
PORT = 33000
BUFFER_SIZE = 1024
ADDRESS = (HOST, PORT)

CLIENT_PRIVATE = 'keys/client_private.pem'
CLIENT_PUBLIC = 'pki/client_public.pem'

SERVER_PRIVATE = 'keys/server_private.pem'
SERVER_PUBLIC = 'pki/server_public.pem'

CA_CERT = 'ca/cert.pem'
SERVER_CERT = 'certs/server_cert.pem'
