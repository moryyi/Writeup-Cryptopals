#!usr/bin/python
# coding: utf-8


import string


# Notice
#   1. Be careful the lowercase and uppercase.
#   2. Space (' ') should also be taken into consideration.
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
        # for chEncryptKey in string.ascii_letters:
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

    def decryptWithKey(self, chEncryptKey):
        _result = [chr(h ^ ord(chEncryptKey)) for h in self.__listEncryptedHexString]
        return ''.join(_result)


if __name__ == "__main__":
    filename = "cipher.txt"
    breaker = SingleByteXORBreaker()
    lineCnt = 0
    with open('record.txt', 'w') as f:
        with open(filename, 'r') as fp:
            while True:
                _currentEncryptString = fp.readline()
                _currentEncryptString = _currentEncryptString.strip()
                if _currentEncryptString == "":
                    break
                else:
                    lineCnt += 1
                _currentEncryptHexList = convertHexString2hexList(_currentEncryptString)
                breaker.setListEncryptedHexString(_currentEncryptHexList)
                _key = breaker.decrypt_bruteAllCharacters()
                _decrypted = breaker.decryptWithKey(_key)
                try:
                    f.write("Line #{}: {}\n".format(lineCnt, _decrypted))
                except UnicodeEncodeError as ex:
                    f.write("Line #{} --> UnicodeEncodeError\n".format(lineCnt))                   


