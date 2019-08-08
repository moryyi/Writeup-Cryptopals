#!usr/bin/python
# coding: utf-8


# Structured cookie parser:
#   From URL-liked parameter string to JSON structure.
# 
#   Notice that: in this challenge, Integer value will not be convert into 
#   integer during the parser phrase.
# 
#   If required, use type() method to convert every possible-integer value
#   into integer.


from Crypto.Cipher import AES
from Crypto import Random
import random, base64


def generateByteString(length):
    return bytes([random.randint(0x00, 0xff) for _ in range(length)])


def blockPKCS7PaddingWithFixedBlockSize(block, targetBlockSize):
    remainSize = targetBlockSize - (len(block) % targetBlockSize)
    _append = ""
    for _ in range(remainSize):
        _append += chr(remainSize)
    # Convert input string into byte string.
    if type(block) == str:
        block = str.encode(block)
    return block + _append.encode()


def structuredStringParser(inputString):
    # 1. Check Empty Input String
    if len(inputString) == 0:
        print("From structuredStringParser: Error: Empty input string.")
        return { }
    
    # 2. Check validation
    _result = { }
    try:
        _parametersList = inputString.split('&')
        for _p in _parametersList:
            _keyValuePair = _p.split('=')
            # 
            if len(_keyValuePair) != 2:
                print('From structuredStringParser: Error: Invalid Parameters.')
                return { }
            _result[_keyValuePair[0]] = _keyValuePair[1]
    except Exception as ex:
        print('From structuredStringParser: Error: Invalid Parameters.')
    return _result


def structuredStringEncoder(structuredParameters):
    # 1. Check whether given parameters are empty.
    if len(structuredParameters.keys()) == 0:
        print("From structuredStringEncoder: Error: Empty Parameters.")
        return ""
    
    # 2. Check validation
    _keyValuePairList = []
    for k in structuredParameters.keys():
        _keyValuePairList.append(
            "{}={}".format(k, structuredParameters[k])
        )
    return '&'.join(_keyValuePairList)


def profile_for(_parameters):
    if '&' in _parameters or '=' in _parameters:
        print("From profile_for: Error: Invalid email address. Containing invalid character ('&' or '=').")
        return { }
    
    _result = {
        "email": _parameters,
        "uid": random.randint(0, 100),
        # "role": random.sample(['user', 'admin'], 1)[0]
        "role": "admin"
    }
    return _result


def encrypt(bPlainText, bAesKey):
    """
    Encrypt encoded string and return encrypted result.
    """
    # Plain text will be automatically padded.
    aes = AES.new(bAesKey, AES.MODE_ECB)
    if type(bPlainText) == str:
        bPlainText = str.encode(bPlainText)
    bPlainText = blockPKCS7PaddingWithFixedBlockSize(bPlainText, 16)
    bCipher = aes.encrypt(bPlainText)
    return bCipher


def decrypt(bCipher, bAesKey):
    """
    Decrypt the encrypted string and return parsed dictionary result.
    """
    aes = AES.new(bAesKey, AES.MODE_ECB)
    if type(bCipher) == str:
        bCipher = str.encode(bCipher)
    bPlainText = aes.decrypt(bCipher)
    # Deal with padding content
    paddingSize = bPlainText[-1]
    bPlainText = bPlainText[:-paddingSize]
    # Parser into user info block
    bPlainText = bPlainText.decode('utf-8')
    userInfoBlock = structuredStringParser(bPlainText)
    return userInfoBlock


if __name__ == "__main__":
    # structuredStringParser("foo=bar&baz=qux&zapzazzle")
    # profile_for("foo@bar.com&role=admin")
    bAesKey = generateByteString(16)
    userInfoBlock = profile_for('foo@bar.com')
    userInfoString = structuredStringEncoder(userInfoBlock)
    bCipher = encrypt(userInfoString, bAesKey)
    b64Cipher = base64.b64encode(bCipher)
    print(b64Cipher)
    decipher = decrypt(bCipher, bAesKey)
    print(decipher)

