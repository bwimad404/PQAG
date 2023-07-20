
import socket
import client_server_auth.config as config
from client_server_auth.src.server import ClientHandler

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # create a socket object
s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1700)
s.bind((config.IP, config.PORT))  # bind to the port
s.listen(20)  # wait for client connection.
while True:
    client_socket, address = s.accept()  # Establish connection with client
    clientThread = ClientHandler(client_socket)  # create a thread for each user
    clientThread.start()  # run thread
