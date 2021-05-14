import binascii, socket, threading, os, sys
from base64 import b64decode, b64encode
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES, PKCS1_OAEP

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

class MAC(object):
    def generate(secret, message):
        h = HMAC.new(secret, digestmod=SHA256)
        h.update(message)

        return h.hexdigest()

    def validate(secret, message, mac):
        h = HMAC.new(secret, digestmod=SHA256)
        h.update(message)

        if h.hexdigest().encode() == mac:
            return 1
        else:
            return -1

# Generate RSA Keys
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

if __name__ == "__main__":
    host_IP = "192.168.1.84"
    host_PORT = 8080
    client_path = os.getcwd()
    keys_path = os.path.join(client_path, 'Keys')
    
    
    # Clients needs sever_pk to work
    # Checks if there is any pair of RSA keys
    if os.path.isdir(keys_path):
        public_key_path = os.path.join(keys_path, 'public.pem')
        secret_key_path = os.path.join(keys_path, 'secret.pem')
        server_pk_path = os.path.join(keys_path, 'public_server.pem')
        if not os.path.isfile(server_pk_path):
            print('Client nees to have server_pk.pem from trusty source!')
            sys.exit()    
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


    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect((host_IP, host_PORT))

    # 1st Client will send his pk & digital signature
    #   cipher_text = RSAe(c_pk, s_pk) & ass = Sign(SHA256(c), c_sk)
    #   c::ass
    
    client_pk = RSA.importKey(open(public_key_path).read())
    client_pk = client_pk.exportKey('PEM')
    client_sk = RSA.importKey(open(secret_key_path).read())
    
    server_pk = RSA.importKey(open(server_pk_path).read())
    server_pk = server_pk.exportKey('PEM')
    
    ass = DigitalSignature.sign(client_pk, secret_key_path)
    print('aqui')
    server.send(client_pk)
    print('ali')
    server.send(ass)
    print('acolá')
    # 2nd Client will receive the symetric key, secret, plus the digital signature from Server
    #   secret::ass
    #   secret = RSAd(c, c_sk) & veracity = verify(SHA256(c), s_pk)
    # secret ==> 256 chr ==> 256*4 = 1024 bits
    c = server.recv(1024)
    digital_signature = server.recv(2048)

    # 3rd veracity == True:
    #   Client starts to use the secret
    #   Communication is now done with AES
    secret = RSACipher.decrypt(c, secret_key_path)
    if DigitalSignature.verify(secret, digital_signature, server_pk_path) == -1:
        print('Veraficade não verificada!')
        sys.exit()
    print('AES agora')

    # 4th Client sends RECEIVE_FLAG to Server with:
    #   c = AESe(RECEIVE_FLAG, secret)
    #   hmac = HMAC(SHA256(c), secret)
    #   c::hmac
    message_flag = hex(1)
    print(message_flag)
    cipher = AESCipher(secret)
    cipher_text = cipher.encrypt(message_flag)
    
    # HMAC
    hmac = MAC.generate(secret, message_flag.encode())
    send = cipher_text + "::" + hmac
    print(send)
    server.send(send.encode())

'''
# 5th AES communications until the end of connection
ciphertext = server.recv(2048)

# Imports Server PK (trusty apriori)
server_pk_path = os.path.join(keys_path, 'public_server.pem')
server_pk = RSA.importKey(open(server_pk_path).read())
server_pk = server_pk.exportKey('PEM')
# Decipher the symetric key
cipher = AESCipher(server_pk)
plaintext = cipher.decrypt(ciphertext)

# Digital Signature of that Key
digital_signature = server.recv(2048)

if DigitalSignature.verify(plaintext.encode(), digital_signature, server_pk_path) == 1:
    # Digital Assignature good
    print('BOAS PUTO!')

    # Client sends OK message
    # Flag == 1, then Client can change messages with Server
    secret = plaintext
    print(secret)
    message_flag = hex(1)
    print(message_flag)
    cipher = AESCipher(secret.encode())
    ciphertext = cipher.encrypt(message_flag)
   
    server.send(ciphertext.encode())
    
    # HMAC
    hmac = MAC.generate(secret.encode(), message_flag.encode())
    server.send(hmac.encode())

else:
    # Disconnect from Server
    print('FDD')

# Backdoor
message = 'Olá bro, isto aqui é super seguro....'

# Client OG public key
client_path = os.getcwd()
keys_path = os.path.join(client_path, 'Keys')
rsa = RSAGenerator(client_path)
rsa.generator()


public_key = RSA.importKey(open(public_key_path).read())
public_key = public_key.exportKey('PEM')
cipher = AESCipher(public_key)
#ciphertext = 
while True:
    1
'''