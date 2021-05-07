
import signal
# o que utilizamos
import binascii, socket, threading, os
from base64 import b64decode, b64encode
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

# HMAC https://pycryptodome.readthedocs.io/en/latest/src/hash/hmac.html
# RSA https://www.dlitz.net/software/pycrypto/api/current/Crypto.public_key.RSA-module.html
# HASH https://pycryptodome.readthedocs.io/en/latest/src/hash/hash.html
# AES implementation
# Credits: https://medium.com/quick-code/aes-implementation-in-python-a82f582f51c2
class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        # 16, 24 or 32 bytes
        self.key = SHA256.new(data=key)
        self.key = self.key.digest()
    
    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        plain_text = plain_text.encode()
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text)
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
        
        return PKCS1_v1_5.new(key).sign(h)

    def verify(message, message_signed, public_key_path):
        key = RSA.importKey(open(public_key_path).read())
        h = SHA256.new(data=message)
        

        try:
           PKCS1_v1_5.new(key).verify(h, message_signed)
           return 1 
        except(ValueError, TypeError):
            return -1
'''
# Login
def ReceiveLoginData(socketClient, AESKey, flag):
    data = socketClient.recv(1024)
    # 1st removes the Padding
    data = RemovePadding(AESKey.decrypt(data))

    # If flag is for creating a new user espectying
    if data == FLAG_QUIT:
        username = 'xxx'
        password = 'xxx'
        # Checks if the hash is equal
    else:
        pass

# Registry
def ReceiveRegistryData(socketClient, AESKey, flag):
    data = socketClient.recv(1024)
    # 1st removes the Padding
    data = RemovePadding(AESKey.decrypt(data))

    if data == FLAG_QUIT:
        # Makes a new entry on passwords files!
        print('ola')
    else:
        pass
'''
# Handshake
def Handshake(socketClient):
    print('asdad')

# Server
def SettingUp(public_key_path, secret_key_path):
    while True:
        # Host and Client data for debugging
        host, client = server.accept()
     
        # Generate a simetric secret in hex (s)
        # Each char ===> 4 bytes
        # So 128*4 = 512 bytes
        # State of Art
        # AES with 128 bits == 3072 bits in RSA == 256 bits in ECC
        # 32 chars ===> 128 bits
        secret = binascii.b2a_hex(os.urandom(32)).hex()
        print('Segredo')
        print(secret)
        
        # Cipher with AES c = (AES(s, pk_s))
        public_key = RSA.importKey(open(public_key_path).read())
        public_key = public_key.exportKey('PEM')
        
        cipher = AESCipher(public_key)
        ciphertext = cipher.encrypt(secret)
        
        # Every data need to be binary to send to client
        host.send(ciphertext.encode())
        
        
        # Digital Signature h, sign = Sign(h(c), sk_s)
        digital_signature = DigitalSignature.sign(ciphertext.encode(), secret_key_path)
        host.send(digital_signature)
        # Sends to client, send(c, sign)
        

if __name__ == "__main__":
    # IP and Port of Server
    host_IP = "192.168.207.15"
    host_PORT = 8080
    server_path = os.getcwd()
    keys_path = os.path.join(server_path, 'Keys')

    # Checks if there is any pair of RSA keys
    if os.path.isdir(keys_path):
        # Needs to check if keys are there
        public_key_path = os.path.join(keys_path, 'public.pem')
        secret_key_path = os.path.join(keys_path, 'secret.pem')
    # If not, creates new pair of RSA Keys and warns the user
    else:
        os.mkdir(keys_path)
        random = Random.new().read
        RSA_key = RSA.generate(2048, random)
        public_key = RSA_key.public_key().exportKey()
        secret_key = RSA_key.exportKey()

        public_key_path = os.path.join(keys_path, 'public.pem')
        secret_key_path = os.path.join(keys_path, 'secret.pem')
        # Writes

        file = open(public_key_path, "wb")
        file.write(public_key)
        file.close()
        file = open(secret_key_path, "wb")
        file.write(secret_key)
        file.close()
    '''
    server = ""
    AESKey = ""
    RecDados = []
    CONNECTION_LIST = []
    FLAG_READY = "Ready"
    FLAG_QUIT = "quit"
    '''
    # Starting Up the Server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host_IP, host_PORT))
    server.listen(0)
    # accept clients
    threading_accept = threading.Thread(
        target=SettingUp, args=[public_key_path, secret_key_path])
    threading_accept.start()
