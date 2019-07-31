#!usr/bin/python
# coding: utf-8


# The hex encoded string:
#   1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
# ... has been XOR'd against a single character.
# Find the key, decrypt the message.
# You can do this by hand. But don't: write code to do it for you.
# How? Devise some method for "scoring" a piece of English plaintext.
# Character frequency is a good metric. 
# Evaluate each output and choose the one with the best score.


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

ENCRYPTED_HEX_STRING = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"


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
        return dicBestEvaluationKey
    
    def __decrypt_oneCharacter(self, chEncryptKey):
        _result = [(ord(chEncryptKey) ^ h) for h in self.__listEncryptedHexString]
        return _result

    
if __name__ == "__main__":
    encryptedHexList = convertHexString2hexList(ENCRYPTED_HEX_STRING)
    breaker = SingleByteXORBreaker()
    breaker.setListEncryptedHexString(encryptedHexList)
    result = breaker.decrypt_bruteAllCharacters()
    print(result)