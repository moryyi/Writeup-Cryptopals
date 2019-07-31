#!usr/bin/python
# coding: utf-8


from Crypto.Cipher import AES
from Crypto import Random
import base64


class AES128CBC:
    def __init__(self):
        self.__key = None
        self.__filename = None
        self.__AES = None
        self.__iv = '\x00' * 16
        return

    def setKey(self, key):
        self.__key = key
        return
    
    def setFilename(self, filename):
        self.__filename = filename
        return
    
    def decrypt_filename(self):
        # Make sure that self.__AES is not None.
        if self.__key == None:
            print("ERROR: Empty key.")
        elif self.__filename == None:
            print("ERROR: Empty filenmame.")
        elif self.__AES == None:
            self.__AES = AES.new(str.encode(self.__key), AES.MODE_CBC, str.encode(self.__iv))
        
        # Read in all data.
        with open(self.__filename, 'r') as fp:
            __data = fp.read().strip()
        __decrypt = self.decrypt(__data)
        return __decrypt

    def decrypt(self, cipher):
        cipher = base64.b64decode(str.encode(cipher))
        __decrypt = self.__AES.decrypt(cipher)
        return __decrypt

    # Used to verify the result.
    def encrypt(self, plainText):
        self.__AES = AES.new(str.encode(self.__key), AES.MODE_CBC, str.encode(self.__iv))
         # Convert from base64 to hex data.
        __encrypt = self.__AES.encrypt(plainText)
        __data = base64.b64encode(__encrypt)
        return __data


if __name__ == "__main__":
    en = AES128CBC()
    en.setKey('YELLOW SUBMARINE')
    en.setFilename('cipher.txt')
    de = en.decrypt_filename()
    with open('decrypt.txt', 'w') as fp:
        fp.write(de.decode('utf-8'))
    ci = en.encrypt(de)
    print(ci)


