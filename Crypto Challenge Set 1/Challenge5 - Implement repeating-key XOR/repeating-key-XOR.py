#!usr/bin/python
# coding: utf-8


# Implement repeating-key XOR
# Here is the opening stanza of an important work of the English language:
#   Burning 'em, if you ain't quick and nimble
#   I go crazy when I hear a cymbal
# Encrypt it, under the key "ICE", using repeating-key XOR.
# In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.
# It should come out to:
#   0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
#   a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
# Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.


# Global Variables
PLAINTEXT = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
KEY = "ICE"
CORRECT_CIPHER = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

class RepeatKeyXOR:
    def __init__(self, plainText, key):
        self.__plainText = plainText
        self.__key = [ord(c) for c in key]
        self.__keyPoint = 0
        self.__keyLength = len(self.__key)
        self.__cipher = ""
        return

    def __getNextKeyElement(self):
        self.__keyPoint = (self.__keyPoint + 1) % self.__keyLength
        return self.__key[self.__keyPoint - 1]

    def encrypt(self):
        cipherHexList = []
        for i in range(len(self.__plainText)):
            cipherHexList.append(
                ord(self.__plainText[i]) ^ self.__getNextKeyElement()
            )
        print(cipherHexList)
        cipherHexStringList = ['{:02x}'.format(x) for x in cipherHexList]
        self.__cipher = ''.join(cipherHexStringList)
        return self.__cipher
    
    def getLastCipher(self):
        return self.__cipher


if __name__ == "__main__":
    rk = RepeatKeyXOR(PLAINTEXT, KEY)
    cipher = rk.encrypt()

    # Determine whether these 2 cipher result are the same.
    print(cipher)
    print(len(cipher))
    print(CORRECT_CIPHER)
    print(len(CORRECT_CIPHER))
    for i in range(len(cipher)):
        if cipher[i] != CORRECT_CIPHER[i]:
            print('{}: {}, {}'.format(i, cipher[i], CORRECT_CIPHER[i]))
            print(cipher[:i+1])
            print(CORRECT_CIPHER[:i+1])
    print(cipher == CORRECT_CIPHER)
    
