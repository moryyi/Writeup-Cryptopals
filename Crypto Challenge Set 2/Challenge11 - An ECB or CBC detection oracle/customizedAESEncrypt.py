#!usr/binpython
# coding: utf-8


# An ECB/CBC detection oracle
# Now that you have ECB and CBC working:
# Write a function to generate a random AES key; that's just 16 random bytes.
# Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.
# The function should look like:
#       encryption_oracle(your-input)
#       => [MEANINGLESS JIBBER JABBER]
# Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.
# Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.
# Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
# 
# Brief explaination:
#   1. Generate random aes key
#   2. Padding plain text
#   3. Encrypt (complete) plain text with chosen mode from ECB and CBC


import random
from Crypto.Cipher import AES
from Crypto import Random
import base64


def generateRandom16ByteString():
    """
    Return 16-byte-long string.
    """
    # return ''.join([chr(random.randint(0x00, 0xff)) for _ in range(16)])
    return bytes([random.randint(0x00, 0xff) for _ in range(16)])

def blockPKCS7PaddingWithFixedBlockSize(block, targetBlockSize):
    remainSize = targetBlockSize - (len(block) % targetBlockSize)
    _append = ""
    for i in range(remainSize):
        _append += chr(remainSize)
    return block + _append.encode()

def encryption_oracle(plainText):
    """
    @param plainText, string
    """
    # Generate random encryption key.
    bAesKey = generateRandom16ByteString()
    # Generate random initialization vector.
    bIV = generateRandom16ByteString()

    print(len(bAesKey))
    print(len(bIV))
    # Append 5 - 10 bytes before / after plainText
    paddedPlainText = bytes([random.randint(0x00, 0xff) for _ in range(random.randint(5, 10))]) \
            + str.encode(plainText) \
            + bytes([random.randint(0x00, 0xff) for _ in range(random.randint(5, 10))])
    paddedPlainText = blockPKCS7PaddingWithFixedBlockSize(paddedPlainText, 16)
    # Encryption procedure.
    _mode = -1
    _cipher = None
    aes = None
    for _ in range(10):
        _mode = random.randint(0, 1)
    if _mode == 0:
        # ECB mode
        print("\t> Mode: ECB")
        aes = AES.new(bAesKey, AES.MODE_ECB)
    else:
        # CBC mode
        print("\t> Mode: CBC")
        aes = AES.new(bAesKey, AES.MODE_CBC, bIV)
    # Encrypt plain text and get cipher.
    _cipher = aes.encrypt(paddedPlainText)

    # # Decryption procedure.
    # # Test only
    # if _mode == 0:
    #     # ECB mode
    #     aes = AES.new(bAesKey, AES.MODE_ECB)
    # else:
    #     # CBC mode
    #     aes = AES.new(bAesKey, AES.MODE_CBC, bIV)
    # _decipher = aes.decrypt(_cipher)
    # print(_decipher)

    # Make cipher printable with base64.
    _b64Cipher = base64.b64encode(_cipher)
    return _b64Cipher


if __name__ == "__main__":
    plainText = "abcdefghijklmnopabcdefghijklmnopabcdefghijklmnop"
    print(encryption_oracle(plainText))
