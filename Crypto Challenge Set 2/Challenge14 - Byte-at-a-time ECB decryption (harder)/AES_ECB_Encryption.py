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
    if type(block) == str:
        block = str.encode(block)
    return block + _append.encode()


def generateByteString(length):
    return bytes([random.randint(0x00, 0xff) for _ in range(length)])


def readFile(filename):
    with open(filename, 'r') as fp:
        content = fp.read()
    return content


def readRowContent(filename):
    with open(filename, 'r') as fp:
        _result = fp.read()
    return _result


def readBase64EncodedContent(filename):
    _aes_key = readRowContent(filename)
    _aes_key = _aes_key.strip()
    return base64.b64decode(_aes_key)


def encryption_oracle(inputString, bAesKey):
    # Pad inputString to block size and convert it into bytes
    if type(inputString) == str:
        inputString = str.encode(inputString)
    # 1. Add prefix
    prefixFilename = 'prefix.txt'
    PREFIX = readBase64EncodedContent(prefixFilename)
    inputString = PREFIX + inputString
    # 2. Add unknown string
    unknownString = base64.b64decode(UNKNOWN_STRING)
    inputString += unknownString
    # 3. Add padding
    bPlainText = blockPKCS7PaddingWithFixedBlockSize(inputString, 16)
    aes = AES.new(bAesKey, AES.MODE_ECB)
    bCipher = aes.encrypt(bPlainText)
    return bCipher


# Global Variables
# 
# Generate 16 bytes aes key
PREFIX = generateByteString(random.randint(0, 16))
AES_KEY = generateByteString(16)
UNKNOWN_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"


if __name__ == "__main__":
    with open('prefix.txt', 'w') as fp:
        fp.write(base64.b64encode(PREFIX).decode('utf-8'))
    # Read in plain text
    filename = "plain.txt"
    plainText = readFile(filename)
    # Encrypt plain text
    cipher = encryption_oracle(plainText, AES_KEY)
    print(base64.b64encode(cipher))
    # Record current key and cipher
    with open('key.txt', 'w') as fp:
        fp.write(base64.b64encode(AES_KEY).decode('utf-8'))
    

    with open('cipher.txt', 'w') as fp:
        fp.write(base64.b64encode(cipher).decode('utf-8'))
