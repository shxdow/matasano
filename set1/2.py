import binascii
from sys import argv
from numpy import bitwise_xor, array2string

def _xor(s1, s2):

    if len(s1) != len(s2):
        return -1

    binary = bitwise_xor(bytearray(binascii.unhexlify(s1)), bytearray(binascii.unhexlify(s2)))

    return array2string(binary)

print(_xor(argv[1], argv[2]))

