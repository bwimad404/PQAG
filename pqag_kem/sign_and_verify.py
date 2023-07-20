from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder, RawEncoder

import nacl
import sys

def gen_key():
    privKey = SigningKey.generate()
    pubKey = privKey.verify_key

    return privKey, pubKey


def save_keys(priK,pubK,filename,filename2):
    open(filename, "wb").write(priK.encode(RawEncoder()))
    open(filename2, "wb").write(pubK.encode(RawEncoder()))

def read_sign_keys(filename):
    priKeyData = open(filename, "rb").read()
    print("this is the original private key")
    print(priKeyData)
    hexed_key = priKeyData.hex()
    final_key = bytes.fromhex(hexed_key)
    return priKeyData

def read_verify_keys(filename):

    pubKeyData = open(filename, "rb").read()
    print(pubKeyData.hex())
    hexed_key = pubKeyData.hex()
    final_key = bytes.fromhex(hexed_key)

    return pubKeyData

def sign_msg(privKey,msg):
    signK =  SigningKey(privKey)
    signature = signK.sign(msg)
    return signature

def verify_sig(pubKey,sig,msg):

    result = False
    vk = VerifyKey(pubKey)
    try:
        vk.verify(sig)
        result = True
    except:
        print("Invalid Signature!",sys.exc_info()[0])

    return result


if __name__ == '__main__':
    priK, pubK = gen_key()
    sign_k_og = priK
    verify_k_og = pubK

    priK2,pubK2 = gen_key()
    print("second pri")
    print (priK2)
    print("second pub")
    print(pubK2)
    filename1 = "my-secret-key"
    filename2 = "my-public-key"
    save_keys(priK,pubK, filename1,filename2)
    sign_key = read_sign_keys(filename1)
    verify_key = read_verify_keys(filename2)
    msg = b"hello world"
    signature = sign_msg(sign_key, msg)
    verification = verify_sig(verify_key, signature, msg)
    print(verification)
    print ("og sign k ", sign_k_og)
    print("reloaded sign k ", sign_key)
    print("og verify k ", verify_k_og)
    print("reloaded verify k ", verify_key)

