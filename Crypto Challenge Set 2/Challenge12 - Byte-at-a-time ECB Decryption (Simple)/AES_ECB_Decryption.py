#!usr/bin/python
# coding: utf-8


from Crypto.Cipher import AES
from Crypto import Random
import base64, random, string


PROBABLE_LETTERS = string.ascii_letters + ' _{}\''


def encryption_oracle(plainText, bAesKey):
    aes = AES.new(bAesKey, AES.MODE_ECB)
    bCipher = aes.encrypt(plainText)
    return bCipher


def readBase64EncodedContent(filename):
    _aes_key = readRowContent(filename)
    _aes_key = _aes_key.strip()
    return base64.b64decode(_aes_key)


def detectBlockSize(bCipher, plainText, bAesKey):
    # Initialize blockSize for loop detection
    _blockSize = 1
    _blockSizeMaximum = len(plainText)
    # for i in range(1, _blockSizeMaximum + 1, 1):
    for i in range(1, 20 + 1, 1):
        _stopFlag = False
        _tmpPlainText = plainText[:i]
        _bTmpPlainText = blockPKCS7PaddingWithFixedBlockSize(str.encode(_tmpPlainText), 16)
        _bTmpCipher = encryption_oracle(_bTmpPlainText, bAesKey)
        # Check length should be set to i
        # PKCS#7 padding with append N bytes to N-byte-long string
        for index in range(i):
            if _bTmpCipher[index] != bCipher[index]:
                _stopFlag = True
                break
        if not _stopFlag:
            _blockSize = i
            break
        else:
            pass
    return _blockSize


def blockPKCS7PaddingWithFixedBlockSize(block, targetBlockSize):
    if type(block) == str:
        block = str.encode(block)
    remainSize = targetBlockSize - (len(block) % targetBlockSize)
    _append = ""
    for _ in range(remainSize):
        _append += chr(remainSize)
    return block + _append.encode()


def readRowContent(filename):
    with open(filename, 'r') as fp:
        _result = fp.read()
    return _result


def breakUnknownString(cipherFileName):
    # The following 3 files (content inside) are used to detect the block size.
    bAesKey = readBase64EncodedContent('key.txt')
    bCipher = readBase64EncodedContent('cipher.txt')
    bPlainText = readRowContent('plain.txt')

    # 1. Break block size
    blockSize = detectBlockSize(bCipher, bPlainText, bAesKey)
    print("> Detected Block Size: {}".format(blockSize))

    # 2. Create dictionary with blockSize
    _prefix = b'A' * (blockSize - 1)
    DIC_PLAIN_CIPHER_MAP = { }
    for c in range(0x00, 0xff + 1, 1):
        _tmp = _prefix + bytes([c])
        _bTmp = blockPKCS7PaddingWithFixedBlockSize(_tmp, blockSize)
        _bCipher = encryption_oracle(_bTmp, bAesKey)[:blockSize]
        DIC_PLAIN_CIPHER_MAP[_tmp] = _bCipher
    
    # 3. Decrypt unknown string byte-by-byte
    bUnknownString = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    decipherHexList = []

    brokenUnknownString = b''
    MaximumDecipherLength = 200
    for i in range(MaximumDecipherLength):
        # Craft dictionary
        currentTotalBlockSize = (i // 16 + 1) * 16
        currentTargetSize = currentTotalBlockSize - 1 - i
        prepending = b'A' * currentTargetSize
        currentCraftInput = prepending + brokenUnknownString
        _record_dic = {}
        for guessChar in range(0x00, 0x100, 1):
            _prefix = currentCraftInput + bytes([guessChar])
            _bTmp = blockPKCS7PaddingWithFixedBlockSize(_prefix, blockSize)
            _record_dic[_prefix] = encryption_oracle(_bTmp, bAesKey)[:currentTotalBlockSize]
        # Crack current unknown byte
        _bPlainText = prepending + bUnknownString
        _bPlainText = blockPKCS7PaddingWithFixedBlockSize(_bPlainText, blockSize)
        _bCipher = encryption_oracle(_bPlainText, bAesKey)[:currentTotalBlockSize]
        for k in _record_dic.keys():
            if _record_dic[k] == _bCipher:
                brokenUnknownString += bytes([k[-1]])
                print("#{} Current character: {}".format(i, bytes([k[-1]])))
                break
    print(brokenUnknownString)
    decipherHexList = [0x64]
    return decipherHexList


if __name__ == "__main__":
    aeskeyFilename = 'key.txt'
    BYTES_AES_KEY = readBase64EncodedContent(aeskeyFilename)

    decipherHexList = breakUnknownString('cipher.txt')
    decipher = [chr(h) for h in decipherHexList]
    print("Decipher:\n\n{}".format(''.join(decipher)))

    bUnknownString = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    if ''.join(decipher) == bUnknownString.decode('utf-8'):
        print('Same')
    else:
        print("Different")


