import sys
import base64
import binascii

def _b64(s):
    bytes = binascii.unhexlify(s)
    r = base64.b64encode(bytes)
    r = r.decode()
    return r
