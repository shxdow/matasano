import binascii
from sys import argv


def _xor(s1, s2):

    if len(s1) != len(s2):
        return -1

    bin1 = int(binascii.unhexlify(s1), 2)
    bin2 = int(binascii.unhexlify(s2), 2)

    ret = bin1 ^ bin2

    return ret

print(_xor(argv[1], argv[2]))

