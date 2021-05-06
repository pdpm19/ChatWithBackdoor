import binascii, socket, threading, os
from base64 import b64decode, b64encode
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

hostIP = "192.168.207.15"
hostPORT = 8080

# AES implementation
# Credits: https://medium.com/quick-code/aes-implementation-in-python-a82f582f51c2
class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = SHA256.new(data=key).digest()
    
    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        return plain_text[:-ord(last_character)]

# Digital Signature
class DigitalSignature(object):
    def sign(message, secret_key_path):
        key = RSA.importKey(open(secret_key_path).read())
        h = SHA256.new(data=message)
        h.digest()
        
        return PKCS1_v1_5.new(key).sign(h)

    def verify(message, message_signed, public_key_path):
        key = RSA.importKey(open(public_key_path).read())
        h = SHA256.new(data=message).digest()

        if PKCS1_v1_5.new(key).verify(h, message_signed):
            return 1
        else:
            return -1


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.connect((hostIP, hostPORT))
clientPath = os.getcwd()
keysPath = os.path.join(clientPath, 'Keys')

# Client will receive symetric key
ciphertext = server.recv(2048)

# Imports Server PK (trusty apriori)
server_pk_path = os.path.join(keysPath, 'public_server.pem')
server_pk = RSA.importKey(open(server_pk_path).read())

# Decipher the symetric key
cipher = AESCipher(server_pk)
plaintext = cipher.decrypt(ciphertext)
print(plaintext)

# Digital Signature of that Key
digital_signature = server.recv(2048)
print(digital_signature)
check = DigitalSignature.verify(plaintext, digital_signature, server_pk_path)

while True:
    1
    