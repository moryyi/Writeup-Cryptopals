#!usr/bin/python
# coding: utf-8


# AES in ECB mode
# The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key
#     "YELLOW SUBMARINE".
# (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).
# Decrypt it. You know the key, after all.
# Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.


from Crypto.Cipher import AES
from Crypto import Random
import base64


class AES128ECB:
    def __init__(self):
        self.__key = None
        self.__cipherFilename = None
        self.__AES = None
        return
    
    def setKey(self, key):
        self.__key = key
        return

    def setCipherFilename(self, filename):
        self.__cipherFilename = filename
        return
    
    def encrypt(self):
        return
    
    def decrypt(self):
        _cipher = ""
        with open(self.__cipherFilename, 'r') as fp:
            while True:
                _t = fp.readline()
                if _t == "":
                    break
                else:
                    _cipher += _t.strip()
        _cipher = base64.b64decode(_cipher)
        self.__AES = AES.new(str.encode(self.__key), AES.MODE_ECB)
        _decipher = self.__AES.decrypt(_cipher)
        print(_decipher)
        return


if __name__ == "__main__":
    aesDecrypter = AES128ECB()
    aesDecrypter.setKey("YELLOW SUBMARINE")
    aesDecrypter.setCipherFilename("cipher.txt")
    aesDecrypter.decrypt()