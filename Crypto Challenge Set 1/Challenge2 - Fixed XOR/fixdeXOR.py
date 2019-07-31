#!usr/bin/python
# coding: utf-8

# Write a function that takes two equal-length buffers and produces their XOR combination.

# If your function works properly, then when you feed it the string:

# 1c0111001f010100061a024b53535009181c
# ... after hex decoding, and when XOR'd against:

# 686974207468652062756c6c277320657965
# ... should produce:

# 746865206b696420646f6e277420706c6179


def FixedXOR(targetHexString01, targetHexString02):
    minHexStringLength = min(len(targetHexString01), len(targetHexString02)) // 2
    _hex01 = bytearray.fromhex(targetHexString01)
    _hex02 = bytearray.fromhex(targetHexString02)
    _result = []
    for i in range(minHexStringLength):
        _result.append(
            _hex01[i] ^ _hex02[i]
        )
    return bytearray.hex(bytearray(_result))

if __name__ == "__main__":
    hexString01 = "1c0111001f010100061a024b53535009181c"
    hexString02 = "686974207468652062756c6c277320657965"
    expectedXORHexString = "746865206b696420646f6e277420706c6179"
    resultString = FixedXOR(hexString01, hexString02)
    print(resultString)
    print(resultString == expectedXORHexString)

