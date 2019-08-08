#!usr/bin/python
# coding: utf-8


from Crypto.Cipher import AES
from Crypto import Random
import base64, random


def blockPKCS7PaddingWithFixedBlockSize(block, targetBlockSize):
    remainSize = targetBlockSize - (len(block) % targetBlockSize)
    _append = ""
    for _ in range(remainSize):
        _append += chr(remainSize)
    return block + _append.encode()


def generateByteString(length):
    return bytes([random.randint(0x00, 0xff) for _ in range(length)])


def readFile(filename):
    with open(filename, 'r') as fp:
        plainText = fp.read()
    return plainText


def encryption_oracle(inputString):
    # Pad inputString to block size and convert it into bytes
    bPlainText = blockPKCS7PaddingWithFixedBlockSize(str.encode(inputString), 16)
    aes = AES.new(AES_KEY, AES.MODE_ECB)
    bCipher = aes.encrypt(bPlainText)
    b64Cipher = base64.b64encode(bCipher)
    b64Cipher = b64Cipher.decode('utf-8')
    return b64Cipher



# Global Variables
# 
# Generate 16 bytes aes key
AES_KEY = generateByteString(16)
UNKNOWN_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"


if __name__ == "__main__":
    # Read in plain text
    filename = "plain.txt"
    plainText = readFile(filename)
    unknownString = base64.b64decode(UNKNOWN_STRING).decode('utf-8')
    plainText += unknownString
    # Encrypt plain text
    cipher = encryption_oracle(plainText)
    print(cipher)
    # Record current key and cipher
    with open('key.txt', 'w') as fp:
        fp.write(base64.b64encode(AES_KEY).decode('utf-8'))
    
    with open('cipher.txt', 'w') as fp:
        fp.write(cipher)
