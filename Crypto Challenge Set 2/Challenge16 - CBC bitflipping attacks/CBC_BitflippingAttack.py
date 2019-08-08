#!usr/bin/python
# coding: utf-8


# Cryptopals
# Challenge set 2, Challenge 16:
#   CBC bitflipping attacks
# 
# This challenge requires 2 functions.
#   Function 1: encryption function
#               1. Pre- and Post-pending input plain text.
#               2. Use random AES key and IV.
#               3. Encrypt it with AES-CBC mode.
# 
#   Function 2: decryption function
#               1. Decryt the cipher.
#               2. Parse the decipher and get the value of key 'admin' (which is not inside the input string).
#               3. Return this result based on the existence of 'admin' (which should always be False).
# Notice:
#   It seems that there is an assumption:
# 
#       During this challenge, the ONLY unknown part is the random AES key
#       that used during the encryption and decryption.
# 
#       The process of pre- & post-padding during the encryption is known to the attackers.


from Crypto.Cipher import AES
from Crypto import Random
import random, base64


# Utilities
def readRowContent(filename):
    with open(filename, 'r') as fp:
        _result = fp.read()
    return _result


def readBase64EncodedContent(filename):
    _aes_key = readRowContent(filename)
    _aes_key = _aes_key.strip()
    return base64.b64decode(_aes_key)


def generateByteString(length):
    """
    Generate random bytes string under given length.
    """
    return bytes([random.randint(0x00, 0xff) for _ in range(length)])



def blockPKCS7PaddingWithFixedBlockSize(block, targetBlockSize):
    remainSize = targetBlockSize - (len(block) % targetBlockSize)
    _append = ""
    for _ in range(remainSize):
        _append += chr(remainSize)
    if type(block) == str:
        block = str.encode(block)
    return block + _append.encode()


def structuredStringParser(inputString):
    # try:
    #     if type(inputString) == bytes:
    #         inputString = inputString.decode('utf-8')
    # except UnicodeDecodeError as ex:
    #     print("From structuredStringParser: Error: UnicodeDecodeError.")
    #     return { }
    if type(inputString) == str:
        inputString = str.encode(inputString)
    # 1. Check Empty Input String
    if len(inputString) == 0:
        print("From structuredStringParser: Error: Empty input string.")
        return { }
    
    # 2. Check validation
    _result = { }
    try:
        _parametersList = inputString.split(b';')
        for _p in _parametersList:
            _keyValuePair = _p.split(b'=')
            # 
            if len(_keyValuePair) != 2:
                print('From structuredStringParser: Error: Invalid Parameters.')
                return { }
            _result[_keyValuePair[0]] = _keyValuePair[1]
    except Exception as ex:
        print('From structuredStringParser: Error: Invalid Parameters.')
    return _result


# Required encryption & decryption functions
def encryption(bPlainText):
    # make sure the input string is byte-string
    if type(bPlainText) == str:
        bPlainText = str.encode(bPlainText)
    if b';' in bPlainText or b'=' in bPlainText:
        print("From encryption: Error: Invalid input. Containing invalid characters.")
        return b''
    # Pending required string.
    bPlainText = PRE_PENDING + bPlainText + POST_PENDING
    bPlainText = blockPKCS7PaddingWithFixedBlockSize(bPlainText, 16)
    # Encrypt with Pre-defined Random key and iv
    aes = AES.new(AES_KEY, AES.MODE_CBC, IV)
    bCipher = aes.encrypt(bPlainText)
    return bCipher


def decryption(bCipher):
    if len(bCipher) == 0:
        print("From decryption: Error: Empty input.")
        return b''
    if type(bCipher) == str:
        bCipher = str.encode(bCipher)
    aes = AES.new(AES_KEY, AES.MODE_CBC, IV)
    bDecipher = aes.decrypt(bCipher)
    bDecipher = truncatePadding(bDecipher)
    # Add-on:
    #   Parse the decipher and try to find key-value-pair 'admin'
    _block = structuredStringParser(bDecipher)
    if b'admin' in _block.keys() and _block[b'admin'] == b'true':
        return True
    else:
        return False
    # return bDecipher


def attackCipher(bCipher):
    if type(bCipher) == str:
        bCipher = str.encode(bCipher)
    # 
    # Attack:
    #   Based on the nature of CBC mode, during decryption process,
    #   Any bits changed in certain block will:
    #       1. Affect current complete block.
    #       2. Affect identical bits in the next block.
    # Notice:
    #   The following vector is crafted based on the input:
    #       InputPlainText = 'ppadminqtrue'
    # 
    #   Convert:
    #       b'%20MCs;userdata='
    #       b'ppadminqtrue;com'
    #   to:
    #       b'\xd6\xf9\xd3\x8e{\x05k\xc5\xb4[\xba\x13r(K\xaf'
    #       b'p;admin=true;com'
    # 
    #   Vector is got with:
    #       b'ppadminqtrue;com' ^ b'p;admin=true;com'
    #   and vector will be XOR with *PREVIOUS* block.
    # 
    _vector = [0, 75, 0, 0, 0, 0, 0, 76, 0, 0, 0, 0, 0, 0, 0, 0]
    cipherHexList = list(bCipher)
    for i in range(len(_vector)):
        cipherHexList[16 + i] ^= _vector[i]
    bNewCipher = bytes(cipherHexList)
    return bNewCipher


def truncatePadding(bDecipher):
    if type(bDecipher) == str:
        bDecipher = str.encode(bDecipher)
    paddingSize = bDecipher[-1]
    bDecipher = bDecipher[0 : -paddingSize]
    return bDecipher


# Global variables
PRE_PENDING = b"comment1=cooking%20MCs;userdata="
POST_PENDING = b";comment2=%20like%20a%20pound%20of%20bacon"
# AES_KEY = generateByteString(16)
# IV = generateByteString(16)
AES_KEY = readBase64EncodedContent('key.txt')
IV = readBase64EncodedContent('iv.txt')


if __name__ == "__main__":
    userdata = b'ppadminqtrue'
    bCipher = encryption(userdata)
    b64Cipher = base64.b64encode(bCipher)
    print(b64Cipher)

    with open('cipher.txt', 'w') as fp:
        fp.write(b64Cipher.decode('utf-8'))
    
    with open('key.txt', 'w') as fp:
        fp.write(base64.b64encode(AES_KEY).decode('utf-8'))

    with open('iv.txt', 'w') as fp:
        fp.write(base64.b64encode(IV).decode('utf-8'))
    
    bCipher = readBase64EncodedContent('cipher.txt')

    # Bitflipping attack
    bCipher = attackCipher(bCipher)

    ifContainAdmin = decryption(bCipher)
    print(ifContainAdmin)
    # for i in range(0, len(bDecipher), 16):
    #     print(bDecipher[i : i + 16])
    


