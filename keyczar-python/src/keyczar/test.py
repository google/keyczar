#!/usr/bin/python2.4
#
# for random testing

from Crypto.Hash import MD5
from Crypto.Cipher import AES
hash=MD5.new()
hash.update('message')
print hash.hexdigest()

aes = AES.new("0123456789ABCDEF", AES.MODE_CBC, "0000000000000000")
cipher = aes.encrypt("FoofFoofFoofFoof")
print cipher
aes = AES.new("0123456789ABCDEF", AES.MODE_CBC, "0000000000000000")
print aes.decrypt(cipher)