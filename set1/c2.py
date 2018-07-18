import binascii
from numpy import bitwise_xor

def _xor(s1, s2):

    if len(s1) != len(s2):
        return -1

    # get the raw bytes
    s1 = bytearray(binascii.unhexlify(s1))
    s2 = bytearray(binascii.unhexlify(s2))

    binary = bitwise_xor(s1, s2)

    # bitwise_xor returns integers, convert them to hex
    binary = map("{:x}".format, binary)

    # return a string
    return ''.join(list(binary))
