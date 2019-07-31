#!usr/bin/python
# coding: utf-8



class AESECBDetecter:
    def __init__(self):
        self.__filename = None
        return
    
    def setFilename(self, filename):
        self.__filename = filename
        return

    def splitHexStringWith16Bytes(self, hexString):
        return [hexString[i:i+32] for i in range(0, len(hexString), 32)]

    def ifHasDuplicateString(self, stringList):
        _result = False
        for i in range(len(stringList)):
            for j in range(i + 1, len(stringList)):
                if stringList[i] == stringList[j]:
                    _result = True
                else:
                    continue
        return _result

    def detect(self):
        lineCnt = 0
        dicRecording = []
        with open(self.__filename, 'r') as fp:
            for _line in fp:
                lineCnt += 1
                _line = _line.strip('\n')
                _list16ByteString = self.splitHexStringWith16Bytes(_line)
                if self.ifHasDuplicateString(_list16ByteString):
                    print("Line #{}: {}".format(lineCnt, _line))
                    _t = {
                            "line": lineCnt,
                            "value": _line,
                            "split": []
                        }
                    for _s in _list16ByteString:
                        print("\t{}".format(_s))
                        _t["split"].append(_s)
                    dicRecording.append(_t)
        return dicRecording


if __name__ == "__main__":
    detecter = AESECBDetecter()
    detecter.setFilename('cipher.txt')
    result = detecter.detect()
    print(result)

