import base64, re
from Crypto.Cipher import AES
from Crypto.Hash import SHA256 as sha256
from Crypto import Random
from os import urandom,path
def encrypt(key, raw ):
    raw = pad(raw)
    iv = Random.new().read( AES.block_size )
    cipher = AES.new( key, AES.MODE_CBC, iv )
    return base64.b64encode( iv + cipher.encrypt( raw ) ).decode("UTF-8")
def decrypt(key, enc,):
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv )
    for padlen in range(1,16):
        try:
            Decrypted = unpad(cipher.decrypt( enc[16:] ).decode("UTF-8"),padlen)
            break
        except:
            'print("Does not have padding length: " + padlen)'
    return Decrypted
    #return cipher.decrypt(enc[16:])
def sha256_hash(input):
    h = sha256.new()
    h.update(input)
    return h.hexdigest()
def keygen():
    hash = sha256_hash(urandom(1024))
    gen = ''
    for i in range(0,32):
        gen += hash[i]
    return gen
def pad(text):
    pad_len = 16 - (len(text) % 16)
    str = text + '|'*pad_len
    return str
def unpad(text,padlen):
    text = text.replace('|','')
    return text
def printmenu():
    print("""1) Encrypt a File (Generates a Random Key)
2) Encrypt Text (Generates a Random Key)
3) Decrypt a File (Needs Key)
4) Decrypt Text (Needs Key)
Q) Quit\n""")
while 1:
    printmenu()
    choice = input("Choice: ")
    if choice == '1':
        filename = input("File to Encrypt: ")
        origfilename, file_ext = path.splitext(filename)
        wfilename = origfilename + ".enc" + file_ext
        wfile = open(wfilename,'w')
        file = open(filename, 'r')
        plainfile = file.read()
        key = keygen()
        wfile.write(encrypt(key, plainfile))
        print("Plain File: " + filename)
        print("Encrypted File: " + wfilename)
        print("Key: " + key)
    elif choice == '2':
        plaintext = input("Text to Encrypt: ")
        key = keygen()
        enc_text = encrypt(key,plaintext)
        print("Un-Encrypted Text: " + plaintext)
        print("Encrypted Text: " + enc_text)
        print("Using Key: " + key)
    elif choice == '3':
        break
    elif choice == '4':
        enc_text = input("Encrypted Text: ")
        key = input("Key: ")
        decrypted_text = decrypt(key, enc_text)
        print("Encrypted Text: " + enc_text)
        print("Decrypted Text: " + decrypted_text)
        print("Using Key: " + key)
    elif choice == 'Q' or choice == 'q':
        break
    else:
        print('\nERROR: Invalid Option\nTo Exit type Q.\n')
