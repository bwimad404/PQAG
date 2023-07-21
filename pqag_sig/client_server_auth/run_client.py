
import socket
import client_server_auth.config as config
from client_server_auth.src.client import Client

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:      # Create a socket object
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1400)
    bufsize = s.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
    s.connect((config.IP, config.PORT))  # connect to sever
    client = Client(s)                                            # create new client object
    client.handle_connection()                                    # handle connection with server

