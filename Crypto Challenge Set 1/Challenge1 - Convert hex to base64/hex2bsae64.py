#!usr/bin/python
# coding: utf-8

# The string:
#   > 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
# should produce:
#   > SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

import base64


def hex2base64(hexString):
    rowHexString = bytearray.fromhex(hexString)
    b64String = base64.b64encode(rowHexString)
    return b64String.decode("utf-8")


if __name__ == "__main__":
    hexString = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expectedResultString = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    resultString = hex2base64(hexString)
    print(resultString)
    print(resultString == expectedResultString)
