# o que utilizamos
# https://docs.python.org/3/library/binascii.html
import binascii, socket, threading, os, sys, time, errno
from base64 import b64decode, b64encode
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES, PKCS1_OAEP



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
        plain_text =plain_text.encode()
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

# RSA implementation
# Credits: https://pythonhosted.org/pycrypto/Crypto.Cipher.PKCS1_OAEP-module.html
class RSACipher(object):
    # Always use the public_key from destiny
    def encrypt(plain_text, key_path):
        key = RSA.importKey(open(key_path).read())
        cipher = PKCS1_OAEP.new(key)
        
        # Return is binary
        return cipher.encrypt(plain_text)
    
    # Always use the our secret_key
    def decrypt(cipher_text, key_path):
        key = RSA.importKey(open(key_path).read())
        cipher = PKCS1_OAEP.new(key)
        
        # Return is binary
        return cipher.decrypt(cipher_text)

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

# HMAC
# Credits: https://pycryptodome.readthedocs.io/en/latest/src/hash/hmac.html
class MAC(object):
    def generate(secret, message):
        h = HMAC.new(secret, digestmod=SHA256)
        h.update(message)

        return h.hexdigest()

    def validate(secret, message, mac):
        h = HMAC.new(secret, digestmod=SHA256)
        h.update(message)

        if h.hexdigest() == mac:
            return 1
        else:
            return -1

# Generate RSA Keys
# Credits: https://www.dlitz.net/software/pycrypto/api/current/Crypto.PublicKey.RSA-module.html
class RSAGenerator(object):
    def __init__(self, keys_path):
        self.keys_path = keys_path

    def generator(self):
        random = Random.new().read
        RSA_key = RSA.generate(2048, random)
        public_key = RSA_key.publickey().exportKey()
        secret_key = RSA_key.exportKey()

        public_key_path = os.path.join(keys_path, 'public.pem')
        secret_key_path = os.path.join(keys_path, 'secret.pem')
        
        # Write sk and pk to separated files
        file = open(public_key_path, "wb")
        file.write(public_key)
        file.close()
        file = open(secret_key_path, "wb")
        file.write(secret_key)
        file.close()

# Global Variables
secret = ''
# Threadpool ===> [(c1_IP, c1_secret), (c2_IP, c2_secret),..., (cn_IP, cn_secret)]
threadpool = []

# Handshake with Digital Signature
def Handshake(host, public_key_path, secret_key_path):
    # 1st Server will receive from the Client the c_pk & digital signature:
    #      c_pk & ass = Sign(SHA256(c_pk), c_sk)
    #      c
    #      ass
    c_pk = host.recv(2048)
    time.sleep(0.5)
    digital_signature = host.recv(2048)
    client_pk_path = os.path.join(keys_path, 'public_client.pem')
    file = open(client_pk_path, "wb")
    file.write(c_pk)
    file.close()
     
    # 2nd Server will check the veracity of recived digital signature: 
    #      veracity = DigitalSignature.verify(c_pk, ass, c_pk)
    if DigitalSignature.verify(c_pk, digital_signature, client_pk_path) == -1:    
        print('Veracidade não verificada!')
        os.remove(client_pk_path)
        # --------------------------------------- #
        # CLOSES THE THREAD
        # Closes that thread
        sys.exit()

    # 3rd Server will generate a simetric secret, secret, in hex
    #      Each char ===> 4 bytes
    #      So 128*4 = 512 bytes
    #      State of Art
    # AES with 128 bits == 3072 bits in RSA == 256 bits in ECC
    # 32 chars ===> 128 bits
    secret = binascii.b2a_hex(os.urandom(32)).hex()
     
      
    # 4th Server will cipher the secret, c, with RSA and sign it: 
    #      c = RSAe(secret, c_pk) & ass = Sign(SHA256(c), s_sk)
    cipher_text = RSACipher.encrypt(secret.encode(), client_pk_path)
     
      
    ass = DigitalSignature.sign(cipher_text, secret_key_path)
     
      
    host.send(cipher_text)
    time.sleep(0.5)
    host.send(ass)
     
    # 5th Wait for confirmation from Client with AES
    received = host.recv(2048)
    received = received.decode()
    cipher_text, hmac = received.split('::')
     
    cipher = AESCipher(secret.encode())
    plain_text = cipher.decrypt(cipher_text)
    if MAC.validate(secret.encode(), plain_text.encode(), hmac) != 1:
        sys.exit()

    print('Feito handshake')
    return secret

# Receive Messages (Client -> Server) 
def ReceiveMessages(host, secret, server_pk_path):
    global connections
    received = host.recv(2048)
    # 1st split the c2 from hmac
    received = received.decode()
    cipher_text2, hmac = received.split('::')
    
    # 2nd check the hmac veracity
    cipher = AESCipher(secret.encode())
    cipher_text1 = cipher.decrypt(cipher_text2)
    
    if MAC.validate(secret.encode(), cipher_text1.encode(), hmac) != 1:
        sys.exit()

    # 3rd decipher to plain_text & saves on log file
    # 3.1 Reads Server PK
    server_pk = RSA.importKey(open(server_pk_path).read())
    server_pk = server_pk.exportKey('PEM')

    # 3.2 Decipher
    cipher = AESCipher(server_pk)
    #plain_text = 'TEntativa'
    plain_text = cipher.decrypt(cipher_text1)

    # 3.3 Opens Log file & writes
    log_dir_path = os.path.join(os.getcwd(), 'log')
    log_file_path = os.path.join(log_dir_path, 'log.txt')
    if os.path.isdir(log_dir_path):
        f = open(log_file_path, 'a+')
        f.write(plain_text+'\n')
        f.close()
    else:
        os.mkdir(log_dir_path)
        f = open(log_file_path, 'a+')
        f.write(plain_text)
        f.close()

    # 4th sends to every client
    for con in connections:
        host = con[0]
        secret = con[1]
        try:
            # accept clients
            threading_accept = threading.Thread(
                target=SendMessage, args=[host, secret, cipher_text1])
            threading_accept.start()
        except IOError as e:
            print('apanhei algo!')
            if e.errno == errno.EPIPE:
                print('con desligada')
                connections.pop(con)


# Send Messages (Sever -> All Clients)
def SendMessage(host, secret, message):
    cipher = AESCipher(secret.encode())
    cipher_text = cipher.encrypt(message)
    hmac = MAC.generate(secret.encode(), message.encode())
    
    send = cipher_text + '::' + hmac
    host.send(send.encode())

    sys.exit()

connections = []
# Server
def SettingUp(server_public_key_path, server_secret_key_path, host, client):
    print('Handshake Phase ', client)
    # Handshake
    secret = Handshake(host, server_public_key_path, server_secret_key_path)
    global connections
    connections.append((host,secret))
    while True:
        # Host and Client data for debugging
        # This thread is on listening until Server gets a new message
        # Now every time that server has a new message, he sends it to the n-client
        #  ReceiveMessage()
        ReceiveMessages(host, secret, server_public_key_path)

if __name__ == "__main__":
    # IP and Port of Server
    host_IP = "192.168.255.112"
    host_PORT = 8080
    server_path = os.getcwd()
    keys_path = os.path.join(server_path, 'Keys')
    
    # Checks if there is any pair of RSA keys
    if os.path.isdir(keys_path):
        public_key_path = os.path.join(keys_path, 'public.pem')
        secret_key_path = os.path.join(keys_path, 'secret.pem')
        
        # Needs to check if keys are there
        if os.path.isfile(public_key_path) and os.path.isfile(secret_key_path):
            pass
        else:
            # Generate RSA Keys
            rsa = RSAGenerator(keys_path)
            rsa.generator()
            public_key_path = os.path.join(keys_path, 'public.pem')
            secret_key_path = os.path.join(keys_path, 'secret.pem')
    # If not, creates new pair of RSA Keys and warns the user
    else:
        os.mkdir(keys_path)
        # Generate RSA Keys
        rsa = RSAGenerator(keys_path)
        rsa.generator()
        public_key_path = os.path.join(keys_path, 'public.pem')
        secret_key_path = os.path.join(keys_path, 'secret.pem')
    
    # Starting Up the Server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host_IP, host_PORT))
    server.listen(0)
    
    while True:
        host, client = server.accept()
        # accept clients
        threading_accept = threading.Thread(
            target=SettingUp, args=[public_key_path, secret_key_path,host, client])
        threading_accept.start()