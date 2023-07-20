"""
This code simulates the processes of the Ground Station Server.
"""

import hashlib
from time import perf_counter_ns
import threading            # for multi-thread support
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import client_server_auth.src.actions as actions
import client_server_auth.config as config
from pqcrypto.pqcrypto.kem.kyber512 import encrypt
from hkdf.hkdf import hkdf_expand, hkdf_extract
from sign_and_verify import *
import hashlib
from Crypto.Random import get_random_bytes

class ClientHandler(threading.Thread):
    def __init__(self, _socket):
        threading.Thread.__init__(self)
        self.socket = _socket
        self.sign_pri = b'\x86\xed\x8fj\xe5Z6M<\x957\x10\xc8\x12\xb0[\xda\xb1\x080\xe9\xd35\x1e\xcd\xfc2o\xfe\xae\xee\x16'
        self.sign_pub = b'\xe3X\xaa\xb3\x0c\x8bh\xbd\x92W\xf3\xa5\xf7\xb5\xcc</\t!\xb1%\x96G\xbaf{\x05\x9e\xb9\x81\x8b\xaf'
        self.sign_pub_as = b'\x89\xaf@\xfe\x83\xee\x7f\xa9\x10\xd5I \xae\x9d\xa5\x15\xf4d{\xb2ii"\x18aD5\xe6\x03P\x8c\x84'
        self.randomnum = 0
        self.identity = b"GS1001"

    def receive(self):
        """
        receives and returns message from client
        catch an error if connection brakes
        """
        input_line = None
        try:
            input_line = self.socket.recv(config.BUFFER_SIZE)

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

    def send(self, message):
        """
        sends message through socket to client
        catch an error if connection brakes
        """
        try:
            self.socket.sendall(message.encode())
        except:
            pass



    def kem(self):

        """ KEM function to generate shared keys
        Receive values are specifically written for chosen primitives.
        Can be modified according to preferred crypto module."""

        print ("Calculating shared keys......")
        public_key = None
        self.send(actions.KEM_ACTION)

        public_key = self.recvall(800)
        as_signature = self.recvall(112)
        ecc_key_as = self.recvall(215)
        rand_bytes = as_signature[96:]

        #verify signature
        t1_start = perf_counter_ns()
        verification = verify_sig(self.sign_pub_as, as_signature[:-16], hashlib.sha256(b"AS1001"+rand_bytes+ecc_key_as+public_key).digest())
        t1_stop = perf_counter_ns()

        if (verification):
            if public_key is None:
                print("No Public Key Received!")
                self.socket.close()
            else:
                #generate classical key-pair
                t2_start = perf_counter_ns()

                ecc_private_key = ec.generate_private_key(
                    ec.SECP384R1()
                )
                ecc_public_key = ecc_private_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                                        serialization.PublicFormat.SubjectPublicKeyInfo)

                t2_stop = perf_counter_ns()

                #derive classical shared key
                t3_start = perf_counter_ns()
                # decode as key from PEM
                ecc_key_as_decoded = load_pem_public_key(ecc_key_as, default_backend())
                shared_key = ecc_private_key.exchange(ec.ECDH(), ecc_key_as_decoded)
                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'handshake data',
                ).derive(shared_key)

                #encapslate PQ keys
                ciphertext, plaintext_original = encrypt(public_key)
                extracted_k = hkdf_extract(plaintext_original, derived_key)
                final_shared_k= hkdf_expand(extracted_k ,info = b"encryption")
                t3_stop = perf_counter_ns()

                t4_start = perf_counter_ns()
                self.randomnum = get_random_bytes(16)
                msg_digest = hashlib.sha256(self.identity+self.randomnum+ciphertext+(b"AS1001"+rand_bytes+ecc_key_as+public_key)).digest()
                # sign a message
                signature = sign_msg(self.sign_pri, msg_digest)
                t4_stop = perf_counter_ns()

                print("Verification")
                print(t1_stop - t1_start)
                print("ECC Key pair")
                print(t2_stop - t2_start)
                print("Shared key derivation")
                print(t3_stop - t3_start)
                print("Signing")
                print(t4_stop - t4_start)
                combined_sig = signature+self.randomnum
                self.socket.send(ciphertext)
                self.socket.send(ecc_public_key)
                self.socket.send(combined_sig)

        else:
            print("Signature Verification Failed!")
            self.socket.close()

    def run(self):
        """
        main function when thread starts
        to manage connection with client
        """
        self.send(b"Connected to server")

        while True:
            self.send(b"\nWhat do you want to do? (kem/quit)")
            self.send(actions.TYPE_ACTION)
            current_type = self.receive()                              # get type

            if current_type is None:                                    # connection broken
                break                                         # register action
            elif current_type == b"kem":
                self.kem()
            elif current_type == b"quit":
                self.send(actions.QUIT_ACTION)         # quit action
                break
            else:
                self.send(b"Unrecognized type")

        # user quit from server
        print ("Client disconnected")
        self.socket.close()                                             # Close the connection

