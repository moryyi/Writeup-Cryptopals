#!usr/bin/python
# coding: utf-8


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
    for i in range(1, paddingSize + 1, 1):
        # Loop from end to start and check each padding bytes
        if block[-i] != paddingSize:
            print('Error: Bad padding. Invalid padding.')
            return False
    return True


if __name__ == "__main__":
    plainText = "Sentence remains to be padded."
    block = blockPKCS7PaddingWithFixedBlockSize(plainText, 16)
    print(block)
    result = ifBlockPKCS7PaddingValidation(b'Sentence remains to be padded.\x03\x03\x03', 16)
    print(result)


