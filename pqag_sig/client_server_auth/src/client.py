"""
This code simulates the processes of the Air Station/Aircraft.
"""

from time import perf_counter_ns
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from sign_and_verify import *
from hkdf.hkdf import hkdf_extract, hkdf_expand
from pqcrypto.pqcrypto.kem.kyber512 import generate_keypair,decrypt
import client_server_auth.config as config
import client_server_auth.src.actions as actions
from Crypto.Random import get_random_bytes
import hashlib


class Client:
    """
    Simple client class to handle connection to server
    """

    def __init__(self, _socket):
        self.socket = _socket
        self.public_key = None
        self.secret_key = None
        self.private_key_as = None
        self.public_key_as = None
        self.identity = b"AS1001"
        self.sign_pri = b"\xefTg!\x1c\xb5\xffx\x06\xb67\xb6\x1b3\x1bV\xda\xach\xeeiU\x05\xbc\xc3\xd6'\xb4\x88\x1d\xb0\x19"
        self.sign_pub = b'\x89\xaf@\xfe\x83\xee\x7f\xa9\x10\xd5I \xae\x9d\xa5\x15\xf4d{\xb2ii"\x18aD5\xe6\x03P\x8c\x84'
        self.sign_pub_gs = b'\xe3X\xaa\xb3\x0c\x8bh\xbd\x92W\xf3\xa5\xf7\xb5\xcc</\t!\xb1%\x96G\xbaf{\x05\x9e\xb9\x81\x8b\xaf'
        self.randomnum = 0

    def send(self, message):
        """
        sends message through socket to server
        """
        try:
            self.socket.sendall(message.encode())

        except:
            pass

    def receive(self):
        """
        receives and returns message from server
        """
        input_line = None  # was None
        try:
            input_line = self.socket.recv(config.BUFFER_SIZE)
            input_line = input_line.decode()
        except:
            pass

        return input_line

    def recvall(self, size):
        result = b''
        remaining = size
        while remaining > 0:
            data = self.socket.recv(remaining)
            result += data
            remaining -= len(data)
        return result

    def take_action(self, action_name):
        """
        decides on base of action_name what action should be taken
        in some actions sends respond to the server.

        """
        input_line = None
        if action_name == actions.QUIT_ACTION or len(action_name) == 0:
            return
        elif action_name == actions.KEM_ACTION:
            t1_start = perf_counter_ns()
            self.public_key, self.secret_key = generate_keypair()  # pq key pair
            t1_stop = perf_counter_ns()
            input_line = self.public_key

            # Generate a classical ECC key-pair.

            t2_start = perf_counter_ns()
            self.private_key_as = ec.generate_private_key(
                ec.SECP384R1()
            )
            self.public_key_as = self.private_key_as.public_key().public_bytes(serialization.Encoding.PEM,
                                                                               serialization.PublicFormat.SubjectPublicKeyInfo)
            t2_stop = perf_counter_ns()

            # sign a message
            t3_start = perf_counter_ns()
            self.randomnum = get_random_bytes(16)
            msg = hashlib.sha256(self.identity + self.randomnum + self.public_key_as + self.public_key).digest()
            signature = sign_msg(self.sign_pri, msg)
            t3_stop = perf_counter_ns()

            combined_sig = signature + self.randomnum
            self.socket.send(self.public_key)
            self.socket.send(combined_sig)
            self.socket.send(self.public_key_as)

            print("PQ Key-pair generation")
            print(t1_stop - t1_start)
            print("ECC key-pair generation")
            print(t2_stop - t2_start)
            print("Signature generation")
            print(t3_stop - t3_start)

            # handling process for after the GS replies
            self.kem_receive_action()


        elif action_name == actions.TYPE_ACTION:
            input_line = input(b">> ")  # get action type
        else:  # other communicate from server
            print(action_name)  # show it
            return

        if len(input_line) == 0:
            input_line = b"__"

        self.send(input_line)  # send answer to server if needed

    def kem_receive_action(self):
        """
        method for final key calculation after the GS responds
        Receive values are specifically written for chosen primitives.
        Can be modified according to preferred crypto module.

        """
        ciphertext = self.recvall(736)
        ecc_key_gs = self.recvall(215)
        gs_signature = self.recvall(112)

        # signature verification
        t4_start = perf_counter_ns()
        verifySig= verify_sig(self.sign_pub_gs, gs_signature[:-16],
                                  hashlib.sha256(b"GS1001" + gs_signature[96:] + ciphertext+(self.identity + self.randomnum + self.public_key_as + self.public_key)).digest())
        t4_stop = perf_counter_ns()

        if verifySig:
            t5_start = perf_counter_ns()
            ecc_key_gs_decoded = load_pem_public_key(ecc_key_gs, default_backend())

            # derive classical shared key
            shared_key = self.private_key_as.exchange(ec.ECDH(), ecc_key_gs_decoded)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_key)

            plaintext_recovered = decrypt(self.secret_key, ciphertext)

            # extract final shared key
            extracted_k = hkdf_extract(plaintext_recovered, derived_key)
            final_shared_k = hkdf_expand(extracted_k, info=b"encryption")
            # final_shared_mac = hkdf_expand(extracted_k, info=b"mac")
            # calculate_mac = hmac.new(final_shared_mac, ciphertext, hashlib.sha256)


            t5_stop = perf_counter_ns()
            print("Signature Verification")
            print(t4_stop - t4_start)
            print("Shared key calculation")
            print(t5_stop - t5_start)
        else:

            print("Signature Verification Failed!")
            self.socket.close()

    def handle_connection(self):
        """
        main function to handle connection with server
        """

        action_name = "_"
        while action_name != actions.QUIT_ACTION and len(action_name) != 0:
            action_name = self.receive()
            actions_array = action_name.splitlines()

            for action in actions_array:
                self.take_action(action)

        print("Connection closed")
        self.socket.close()  # Close the socket when done
