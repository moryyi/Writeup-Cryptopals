#!usr/bin/python
# coding: utf-8


# The hex encoded string:

# 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
# ... has been XOR'd against a single character.
# Find the key, decrypt the message.

# You can do this by hand. But don't: write code to do it for you.

# How? Devise some method for "scoring" a piece of English plaintext.
# Character frequency is a good metric. 
# Evaluate each output and choose the one with the best score.


import string


# Global Variable
# LETTER_FREQUENCY
#   Data from Wikipedia.
LETTER_FREQUENCY = {
    'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253,
    'e': 0.12702, 'f': 0.02228, 'g': 0.02015, 'h': 0.06094,
    'i': 0.06966, 'j': 0.00153, 'k': 0.00772, 'l': 0.04025,
    'm': 0.02406, 'n': 0.06749, 'o': 0.07507, 'p': 0.01929,
    'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
    'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150,
    'y': 0.01974, 'z': 0.00074
}


def hexString2hexList(hexString):
    _result = []
    for i in range(0, len(hexString), 2):
        _result.append(
            int(hexString[i:i+2], 0x10)
        )
    return _result


def XORHexStringWithCharacter(cipherHexList, targetCharacter):
    _result = []
    for i in range(len(cipherHexList)):
        _result.append(cipherHexList[i] ^ ord(targetCharacter))
    return _result


def Evaluate(decipherHexList):
    _LETTER_OCCURANCE = { }
    for _hex in decipherHexList:
        _c = ''
        if chr(_hex) not in string.ascii_letters:
            continue
        else:
            # Convert all character to Lowercase
            if chr(_hex) in string.ascii_uppercase:
                _c = chr(_hex + 32)
            else:
                _c = chr(_hex)
            if _c in _LETTER_OCCURANCE.keys():
                _LETTER_OCCURANCE[_c] += 1
            else:
                _LETTER_OCCURANCE[_c] = 1
    
    # Calculate frequency according to each characters' occurance
    _total_occurance = sum(_LETTER_OCCURANCE.values())
    for _k in _LETTER_OCCURANCE.keys():
        _LETTER_OCCURANCE[_k] /= _total_occurance
    
    # Calculate evaluation value
    # _evaluation: lower, the better
    _evaluation = 0.0
    for _k in _LETTER_OCCURANCE.keys():
        _evaluation += abs(LETTER_FREQUENCY[_k] - _LETTER_OCCURANCE[_k])
    return _evaluation


def De_SingleByteXORCipher(cipherHexString):
    cipherHexList = hexString2hexList(cipherHexString)
    evaluationList = { }
    for c in string.ascii_letters:
        _XOR_Result = XORHexStringWithCharacter(cipherHexList, c)
        _result = [chr(x) for x in _XOR_Result]
        # print("{}: {}".format(c, ''.join(_result)))
        evaluationList[c] = Evaluate(_XOR_Result)
    evaluationSortedKeyList = sorted(evaluationList, key=evaluationList.__getitem__)
    return evaluationSortedKeyList[0:5]


def decryptHexStringWithCharater(cipherHexString, possibleEncryptKeyList):
    cipherHexList = hexString2hexList(cipherHexString)
    for c in possibleEncryptKeyList:
        _XOR_Result = XORHexStringWithCharacter(cipherHexList, c)
        _result = [chr(x) for x in _XOR_Result]
        print("\t{}: {}".format(c, ''.join(_result)))
    return


if __name__ == "__main__":
    cipherHexString = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    # cipherHexString = "0e3647e8592d35514a081243582536ed3de6734059001e3f535ce6271032"
    possibleEncryptKeyList = De_SingleByteXORCipher(cipherHexString)
    decryptHexStringWithCharater(cipherHexString, possibleEncryptKeyList)
    # Result: 
    #   X: Cooking MC's like a pound of bacon

