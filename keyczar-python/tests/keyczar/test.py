#!/usr/bin/python2.4
#
# for random testing

from Crypto.Hash import MD5
from Crypto.Cipher import AES
from keyczar import keys
from keyczar import keyinfo
from keyczar import keyczar
from keyczar import util

import os

TEST_DATA = os.path.realpath(os.path.join(os.getcwd(), "..", "..", "testdata"))

hash=MD5.new()
hash.update('message')
print hash.hexdigest()

aes = AES.new("0123456789ABCDEF", AES.MODE_CBC, "0000000000000000")
cipher = aes.encrypt("FoofFoofFoofFoof")
print cipher
aes = AES.new("0123456789ABCDEF", AES.MODE_CBC, "0000000000000000")
print aes.decrypt(cipher)

hmac = keys.GenKey(keyinfo.HMAC_SHA1)
print hmac

msg = "Hello World"
sig = hmac.Sign(msg)
print sig
print hmac.Verify(msg, sig)

input = "Hello Google"
crypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, "aes"))
print "Primary", crypter.Encrypt(input)  # primary
activeAes = crypter.GetKey("8AqKiQ")  # active
print "Active", util.Encode(activeAes.Encrypt(input))

signer = keyczar.Signer.Read(os.path.join(TEST_DATA, "hmac"))
print "Primary Sign", signer.Sign(input)
activeHmac = signer.GetKey("vAOFlA")
print "Active Sign", util.Encode(activeHmac.Header() + activeHmac.Sign(input))