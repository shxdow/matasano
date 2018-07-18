'''
'''

from binascii import unhexlify, hexlify
from string import ascii_lowercase, ascii_letters
from numpy import bitwise_xor
from time import sleep
from collections import Counter 

def _single_xor(s1):

    s = ""
    ptext = ""
    max_e = 0

    # get the raw bytes
    s1 = unhexlify(s1)

    for c in list(ascii_letters):
        s = ""
        s_ascii = ""
        c = str(ord(c))
        c = c.encode()

        # xor the input string against the c character
        for e in s1:
            e = str(e)
            e = e.encode()
            s += '{:02x}'.format(bitwise_xor(int(c), int(e)))
        print(Counter(bytes.fromhex(str(s)).decode('ascii')), end='')
            #  print(Counter(s))
            #  s = ''.join('{:X}'.format(i) for i in s)
        #  try:
        #      print("\033[K [*] key: " + chr(int(c.decode())) + "\tfreq('e'): " + str(s.count('65') + s.count('97')) + "\tmax freq:\t" + str(max_e) + "\ts: " + bytes.fromhex(str(s)).decode('ascii'), end='\n', flush=True)
        #  except ValueError as e:
        #      print(s + str(e))
            
        #  print("\033[K [*] key: " + chr(int(c.decode())) + "\tfreq('e'): " + str(s.count('65') + s.count('97')) + "\tmax freq:\t" + str(max_e) + "\ts: " + s, end='\r')
        #  sleep(0.151)
            #  sleep(0.001)

        if s.count('65') > max_e or s.count('97') > max_e:
            ptext = s
            max_e = s.count('65') + s.count('97')
            #  print("  current letter " + c.decode() + " | highest number of e's:" + str(max_e), '\r')

    #  print('\n [!] most likely string: ' + bytes.fromhex(str(ptext)).decode('ascii'), end='\n', flush=True)
