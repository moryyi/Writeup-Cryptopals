#!usr/bin/python
# coding: utf-8

# https://cryptopals.com/sets/1/challenges/6


import base64
import string
import itertools


# Global Variable
# LETTER_FREQUENCY
#   Data from Wikipedia.
#   'a', 'e', 'h', 'i', 'n', 'o', 'r', 's', 't'
LETTER_FREQUENCY = {
    'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253,
    'e': 0.12702, 'f': 0.02228, 'g': 0.02015, 'h': 0.06094,
    'i': 0.06094, 'j': 0.00153, 'k': 0.00772, 'l': 0.04025,
    'm': 0.02406, 'n': 0.06749, 'o': 0.07507, 'p': 0.01929,
    'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
    'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150,
    'y': 0.01974, 'z': 0.00074,
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253,
    'E': 0.12702, 'F': 0.02228, 'G': 0.02015, 'H': 0.06094,
    'I': 0.06094, 'J': 0.00153, 'K': 0.00772, 'L': 0.04025,
    'M': 0.02406, 'N': 0.06749, 'O': 0.07507, 'P': 0.01929,
    'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
    'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150,
    'Y': 0.01974, 'Z': 0.00074, ' ': 0.13000
}


# Utilities
def convertHexString2hexList(hexString):
    _result = []
    for i in range(0, len(hexString), 2):
        _result.append(
            int(hexString[i:i+2], 0x10)
        )
    return _result


# Classes
class SingleByteXORBreaker:
    def __init__(self):
        self.__listEncryptedHexString = None
        self.__dicKeyEvaluationScore = []
        return
    
    def setListEncryptedHexString(self, listEncryptedHexString):
        self.__listEncryptedHexString = listEncryptedHexString
        return

    def __getEvaluationScore(self, listDecryptedHexString):
        return sum([LETTER_FREQUENCY.get(chr(c), 0) for c in listDecryptedHexString])

    def decrypt_bruteAllCharacters(self):
        self.__dicKeyEvaluationScore = []
        # Iterate all possible ASCII characters.
        for chEncryptKey in [chr(h) for h in range(0, 255)]:
            listTmpDecryptedHexString = self.__decrypt_oneCharacter(chEncryptKey)
            self.__dicKeyEvaluationScore.append(
                {
                    "key": chEncryptKey,
                    "score": self.__getEvaluationScore(listTmpDecryptedHexString),
                    "decryption": ''.join([chr(h) for h in listTmpDecryptedHexString])
                }
            )
        dicBestEvaluationKey = sorted(self.__dicKeyEvaluationScore, key=lambda x: x["score"], reverse=True)[0]
        return dicBestEvaluationKey["key"]
    
    def __decrypt_oneCharacter(self, chEncryptKey):
        _result = [(ord(chEncryptKey) ^ h) for h in self.__listEncryptedHexString]
        return _result


class RepeatKeyXorBreaker:
    def __init__(self):
        self.__possibleKeySize_lower = 2
        self.__possibleKeySize_upper = 40
        self.__filename = None
        self.__listEncryptedHex = []
        self.__possibleKeySizeList = []
        self.__possibleKeyList = []
        self.__listVerticalBlock = []
        return
    
    def setFilename(self, filename):
        self.__filename = filename
        return

    def __readAllEncryptedHex(self):
        with open(self.__filename, 'r') as fp:
            _t = fp.read()
        _t = base64.b64decode(str.encode(_t)).decode('utf-8')
        self.__listEncryptedHex = [ord(c) for c in _t]
        return

    def __getEditDistance(self, string01HexList, string02HexList):
        """Edit Distance
        Number of difference bits between 2 equal-length strings.
        """
        if len(string01HexList) != len(string02HexList):
            return -1
        EditDistance = ""
        for i in range(len(string01HexList)):
            EditDistance += '{:b}'.format(string01HexList[i] ^ string02HexList[i])
        _disBinStr = EditDistance.split('0')
        _disBinStr = ''.join(_disBinStr)
        return len(_disBinStr)
    
    def __getPossibleKeySize(self):
        dic_KeySize_EditDistance = []
        for currentKeySize in range(self.__possibleKeySize_lower, self.__possibleKeySize_upper + 1):
            # Read 2 currentKeyLengh-long sentences.
            # Notice:
            #   Calculate each 2 currentKeyLength-long sentences
            #   through the complete encrypted file.
            _currentDistance = 0.0
            for i in range(len(self.__listEncryptedHex) // currentKeySize):
                _currentDistance += self.__getEditDistance(
                    self.__listEncryptedHex[(i    ) * currentKeySize : (i + 1) * currentKeySize],
                    self.__listEncryptedHex[(i + 1) * currentKeySize : (i + 2) * currentKeySize]
                ) / currentKeySize
            dic_KeySize_EditDistance.append(
                {
                    "size": currentKeySize,
                    "distance": _currentDistance / (len(self.__listEncryptedHex) // currentKeySize)
                }
            )
        # Sort these distance and select the minimum.
        keyInfoBlock = sorted(dic_KeySize_EditDistance, key=lambda x: x["distance"])
        self.__possibleKeySizeList = [k['size'] for k in keyInfoBlock[:1]]
        return

    def __createVerticalBlock(self, keySize):
        self.__listVerticalBlock = [[] for _ in range(keySize)]
        for i in range(len(self.__listEncryptedHex) // keySize):
            _t = self.__listEncryptedHex[i * keySize : (i + 1) * keySize]
            for j in range(keySize):
                self.__listVerticalBlock[j].append(_t[j])
        return

    def breakKey(self):
        # 1. Read cipher data inside. Convert them into hex digit.
        self.__readAllEncryptedHex()
        # 2. Get possible keySize.
        self.__getPossibleKeySize()
        # 3. Iterate each line to form the key with each keySize.
        singleByteXORBreaker = SingleByteXORBreaker()
        for keySize in self.__possibleKeySizeList:
            self.__createVerticalBlock(keySize)
            _listCurrentKey = []
            for i in range(keySize):
                singleByteXORBreaker.setListEncryptedHexString(self.__listVerticalBlock[i])
                _listCurrentKey.append(
                    singleByteXORBreaker.decrypt_bruteAllCharacters()
                )
            self.__possibleKeyList.append(''.join(_listCurrentKey))
        # Decrypt cipher with key.
        decrypter = RepeatKeyXOR()
        for i in range(len(self.__possibleKeyList)):
            _key = self.__possibleKeyList[i]
            _filename = "./decryptFile/key_{}.txt".format(i)
            decrypter.setKey(_key)
            decrypter.setFilename(_filename)
            print("Start with key: {}".format(_key))
            decrypter.decrypt(self.__listEncryptedHex)
        print("Finished.")
        return

class RepeatKeyXOR:
    def __init__(self):
        self.__filename = None
        self.__key = []
        self.__keyPoint = 0
        self.__keyLength = 0
        return

    def __getNextKeyElement(self):
        self.__keyPoint = (self.__keyPoint + 1) % self.__keyLength
        return self.__key[self.__keyPoint - 1]

    def setKey(self, key):
        self.__key = [ord(k) for k in key]
        self.__keyLength = len(self.__key)
        return

    def setFilename(self, filename):
        self.__filename = filename
        return

    def decrypt(self, listEncryptedHex):
        listDecryptedHex = []
        for i in range(len(listEncryptedHex)):
            _k = self.__getNextKeyElement()
            listDecryptedHex.append(
                chr(listEncryptedHex[i] ^ _k)
            )
        with open(self.__filename, 'w') as fp:
            fp.write("############################\n")
            fp.write("Current key: {}\n".format(''.join([chr(h) for h in self.__key])))
            fp.write("############################\n\n\n")
            fp.write(''.join(listDecryptedHex))
        return
    

if __name__ == "__main__":
    filename = "b64_cipher.txt"
    breaker = RepeatKeyXorBreaker()
    breaker.setFilename(filename)
    breaker.breakKey()
