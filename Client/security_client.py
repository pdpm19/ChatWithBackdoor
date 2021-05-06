def DigitalSignature(path):
    key = RSA.importKey(open('private.pem').read())
    f = open(path, 'r')
    fread = f.read()

    hash = SHA512.new()
    hash.update(fread)
    hash.digest()

    ass = open(path+".sign", "wb+")
    digitalSign = pkcs1.new(key).sign(hash)
    ass.write(digitalSign)
    ass.close()

def encrypt(key, iv, in_filename, out_filename=None, chunksize=64*1024):
    AESKey = AES.new(key, AES.MODE_CBC, iv)

    if not out_filename:
        out_filename = in_filename + '.enc'
    filesize = os.path.getsize(in_filename)


    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                #print(chunk)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b" " * (16 - len(chunk) % 16)

                outfile.write(AESKey.encrypt(chunk))