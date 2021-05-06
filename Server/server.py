
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
# RSA https://www.dlitz.net/software/pycrypto/api/current/Crypto.PublicKey.RSA-module.html
# HASH https://pycryptodome.readthedocs.io/en/latest/src/hash/hash.html
# AES implementation
# Credits: https://medium.com/quick-code/aes-implementation-in-python-a82f582f51c2
class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        # 16, 24 or 32 bytes
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

# Handshake
def Handshake(socketClient):
    print('asdad')

# Server
def SettingUp(publicPath, secretPath):
    while True:
        # Host and Client data for debugging
        host, client = server.accept()
     
        # Generate a simetric secret in hex (s)
        # Each char ===> 4 bytes
        # So 128*4 = 512 bytes
        secret = binascii.b2a_hex(os.urandom(128)).hex()
        # print(secret)
        
        # Cipher with AES c = (AES(s, pk_s))
        publicKey = RSA.importKey(open(publicPath).read())
        publicKey = publicKey.exportKey('PEM')
        # print(publicKey)
        cipher = AESCipher(publicKey)
        ciphertext = cipher.encrypt(secret)
        
        # Every data need to be binary to send to client
        host.send(ciphertext.encode())
        
        # Digital Signature h, sign = Sign(h(c), sk_s)
        digital_signature = DigitalSignature.sign(ciphertext.encode(), secretPath)
        host.send(digital_signature)
        # Sends to client, send(c, sign)
        

if __name__ == "__main__":
    # IP and Port of Server
    hostIP = "192.168.207.15"
    hostPORT = 8080
    serverPath = os.getcwd()
    keysPath = os.path.join(serverPath, 'Keys')

    # Checks if there is any pair of RSA keys
    if os.path.isdir(keysPath):
        # Needs to check if keys are there
        publicPath = os.path.join(keysPath, 'public.pem')
        secretPath = os.path.join(keysPath, 'secret.pem')
    # If not, creates new pair of RSA Keys and warns the user
    else:
        os.mkdir(keysPath)
        random = Random.new().read
        RSAKey = RSA.generate(2048, random)
        publicKey = RSAKey.publickey().exportKey()
        secretKey = RSAKey.exportKey()

        publicPath = os.path.join(keysPath, 'public.pem')
        secretPath = os.path.join(keysPath, 'secret.pem')
        # Writes

        file = open(publicPath, "wb")
        file.write(publicKey)
        file.close()
        file = open(secretPath, "wb")
        file.write(secretKey)
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
    server.bind((hostIP, hostPORT))
    server.listen(0)
    # accept clients
    threading_accept = threading.Thread(
        target=SettingUp, args=[publicPath, secretPath])
    threading_accept.start()
