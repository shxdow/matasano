import c3
from sys import modules
from imp import reload
from time import sleep

str1 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"


#  while 1:
print("\033[2J\033[1;1H", end="\r")
#  reload(modules['c3'])
c3._single_xor(str1)
    #  sleep(1)

