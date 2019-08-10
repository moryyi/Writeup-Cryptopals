#!usr/bin/python
# coding: utf-8


# Padding Oracle Attack Explaination Blog
# https://robertheaton.com/2013/07/29/padding-oracle-attack/



from Crypto.Cipher import AES
from Crypto import Random

import random
import base64


# Utilities
def writeBase64ContentIntoFile(filename, plainContent):
    with open(filename, 'w') as fp:
        fp.write(base64.b64encode(plainContent).decode('utf-8'))
    return


def readBase64Content(filename):
    with open(filename, 'r') as fp:
        _result = fp.read()
    _result = base64.b64decode(_result)
    return _result

def generateByteString(length):
    return bytes([random.randint(0x00, 0xff) for _ in range(length)])


# PKCS#7 Padding function
def blockPKCS7PaddingWithFixedBlockSize(block, targetBlockSize):
    if type(block) == str:
        block = str.encode(block)
    remainSize = targetBlockSize - (len(block) % targetBlockSize)
    _append = ""
    for _ in range(remainSize):
        _append += chr(remainSize)
    return block + _append.encode()


# PKCS#7 Padding Validation
def ifBlockPKCS7PaddingValidation(block, targetBlockSize):
    # Check whether is multiple of given block size.
    if len(block) % targetBlockSize:
        print('Error: Bad padding. Not align to block size.')
        return False
    # Get padding length
    # Notice    : when using [] operation in byte string,
    #           we will get 10-based digital result of each character.
    # Example   : a = b'a\x02'
    #           a[0] = 97, a[1] = 2
    paddingSize = block[-1]
    if paddingSize == 0x00:
        paddingSize = 0x10
    print("\t>Detect padding size: {}".format(hex(paddingSize)))
    for i in range(1, paddingSize + 1, 1):
        # Loop from end to start and check each padding bytes
        if block[-i] != paddingSize:
            print('Error: Bad padding. Invalid padding.')
            return False
        else:
            pass
    return True


def truncatePadding(bDecipher):
    if type(bDecipher) == str:
        bDecipher = str.encode(bDecipher)
    paddingSize = bDecipher[-1]
    _result = None
    _ifValid = True
    # If paddingSize is valid:
    if paddingSize not in range(1, 16 + 1):
        print("Error: Invalid padding found in decryption result.")
        _result = bDecipher
    else:
        for i in range(paddingSize):
            if bDecipher[-i - 1] != paddingSize:
                _result = bDecipher
                print('Error: Invalid padding: padding size error.')
                _ifValid = False
                break
        if _ifValid:
            _result = bDecipher[:-paddingSize]
    return _result


# Required functions
def encryption():
    # bRandomPlainText = BYTE_RANDOM_STRINGS_LIST[random.randint(0, len(BYTE_RANDOM_STRINGS_LIST) - 1)]
    bRandomPlainText = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d'
    bPlainText = blockPKCS7PaddingWithFixedBlockSize(bRandomPlainText, 16)
    # Generate IV each time
    # Return IV with cipher text.
    # bIV = generateByteString(16)
    bIV = readBase64Content('iv.txt')
    aes = AES.new(bAesKey, AES.MODE_CBC, bIV)
    bCipher = aes.encrypt(bPlainText)
    return bCipher, bIV


def decryption(bCipher, bIV):
    if type(bCipher) == str:
        bCipher = str.encode(bCipher)
    if type(bIV) == str:
        bIV = str.encode(bIV)
    
    # Decrypt cipher
    aes = AES.new(bAesKey, AES.MODE_CBC, bIV)
    bDecipher = aes.decrypt(bCipher)
    print("> Current Decipher: {}".format(bDecipher))
    # if not ifBlockPKCS7PaddingValidation(bDecipher, 16):
    #     print("Error: Invalid padding.")
    #     return b''
    # else:
    #     bDecipher = truncatePadding(bDecipher)
    #     return bDecipher
    return ifBlockPKCS7PaddingValidation(bDecipher, 16)


# Side-channel Attack
def AES_CBC_PaddingOracleAttack(bCipher, bIV):
    bCipherVector = b''
    return



def breakTest(bCipher, bIV):
    if type(bCipher) == str:
        bCipher = str.encode(bCipher)
    if type(bIV) == str:
        bIV = str.encode(bIV)
    
    bCipher01 = bCipher[:16]
    bCurrectPlaintext01 = b'\x00' * 16
    # Attack the last byte in the first cipher block.
    # bCipherPrependingVector = generateByteString(15)
    bCipherPrependingVector = bIV[:15]
    for lastByte in range(0x00, 0x100):
        bAttackVector = bCipherPrependingVector + bytes([lastByte]) + bCipher01
        print("\n> Current attack vector: {}".format(list(bAttackVector)))
        print("> Current last byte of cipher: {}".format(bCipher01[-1]))
        if decryption(bAttackVector, bIV):
            print("> Valid Padding. Last byte: {}".format(lastByte))
            bCurrectPlaintext01 = bCurrectPlaintext01[:15] + bytes([lastByte ^ 0x01 ^ bCipher01[-1]])
            print("> Current break plaintext: {}".format(bCurrectPlaintext01))
            break
        else:
            print("> Invalid Padding. Current last byte: {}".format(lastByte))    
    return


# Global variables
# List of strings to be selected randomly.
BYTE_RANDOM_STRINGS_LIST = [
    b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
    b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
    b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
    b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
    b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
    b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
    b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
    b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
    b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
    b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
]

# bAesKey = generateByteString(16)
bAesKey = readBase64Content('key.txt')

# Main function
if __name__ == "__main__":
    bCipher, bIV = encryption()
    # writeBase64ContentIntoFile('cipher.txt', bCipher)
    # writeBase64ContentIntoFile('iv.txt', bIV)
    # writeBase64ContentIntoFile('key.txt', bAesKey)
    # bCipher = readBase64Content('cipher.txt')
    # bIV = readBase64Content('iv.txt')
    b64Cipher = base64.b64encode(bCipher)
    # b64IV = base64.b64encode(bIV)
    # print("Base64-encoded cipher: {}\nBase64-encoded IV: {}".format(b64Cipher, b64IV))
    
    # 
    # Test Only
    breakTest(bCipher, bIV)
    bDecipher = decryption(bCipher, bIV)
    print("Decryption result : {}".format(bDecipher))
