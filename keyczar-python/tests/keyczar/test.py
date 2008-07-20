#!/usr/bin/python2.4
#
# for random testing

from Crypto.Hash import MD5
from Crypto.Cipher import AES
from keyczar import keys
from keyczar import keyinfo
from keyczar import keyczar
from keyczar import util
from tlslite.utils import keyfactory

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
print "Primary AES", crypter.Encrypt(input)  # primary
activeAes = crypter.GetKey("y2W2qg")  # active
print "Active AES", util.Encode(activeAes.Encrypt(input))

signer = keyczar.Signer.Read(os.path.join(TEST_DATA, "hmac"))
print "Primary HMAC Sign", signer.Sign(input)
activeHmac = signer.GetKey("vAOFlA")
print "Active HMAC Sign", util.Encode(activeHmac.Header() + activeHmac.Sign(input))

openssl = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAybkyIBcnwJkjTiBvwwMFHcXSzwZzuARs0Dp/xuXtqvlVqGSZ
nJL4VS8Q9VTM346naniV9z17zIfLWVdmP1l44SySvrnVOlNv1PxoC7086NkcAAlj
PCdgNVbKK2f7ex9K7jERb78kd1IS3eCMRdIBa01lcjXBoii8zumblDacCWDkWET4
AQRN9A/ZsoiSh5LInnABrsp6R7Gy0NzthBNVPPW787ultydyDspc1XARgchp+Mqx
j6y77VGA0jsKJL2nrMBx83296UwdQBetOUIBNEGKwYEN3LvgRhE6EiOiVWrHbsvb
9zoT4B9a/E52NnbO4zQ5yV18fhGzFRZdteeUEwIDAQABAoIBAARhSAxYVF2jNZgJ
rkOOujq2Q+iI3FRfjDlNO98GuQ1gUpLQdGFo84lt9zFMgRJNl6cBLUhsBlcfj7PF
6QtxFuXUwO7xPAcDLsdyH5Q5rKvlou0BRy1UMYuW8dbVcClxOYBIgndpsBIDLzOw
H3uYnr1EtfIv5p9twQPBIMasFOFDNmvPJFyXLPjj7aH8jk8/AzxO/VdMm3zz0n7a
C9+WlkPIMjWDJs8wk6JjhIzihhMzSeRk3nhjax1jrWgyWM3tuPES2G6yAdSA6z9B
WA+5TwuXqTZ6FrYCn8Hhorxsjg8+mxsKkSf7p/pfd3+nN5K2fguc6ez/I+CYby/x
ZB5JaTkCgYEA9fONXov+mNTGYAGyaxMtcu1YXgw9iz2eHCZH7e1C7s2FAfA3sLcA
X8GH0IRvXoptSBRnXCwtBRH+evnHHaMaxlmqhIgxxvhUOsBTeJyax9sYyEV63mU7
q/4LYOc2Dfn9N5Xkjfy6RwRetjLOaG0I0tF8EPajakRdrJspQAVCOz0CgYEA0fcO
SAKCGSK5GaN9aMtpBqg8lQLOotcbyI7HmaaQBZT09LbP/1+cZiRlGaWLDPd4cJD0
5fu3Np8YO0yInMKqdZmlN80VijBWvN5J0MEbTVXLPvOawBcDZPGZb7wOah3IK1iD
Pmhz7wjT6pE9/T+c+4K0duqkU2W5GgSGva42QY8CgYBclUfcFVrLcR0Tus/M2rU7
E/k1venU5mcENazR9YRCnH67EhAEp36ujQ1xAslhjz4/6d5WphJ0XCetZyT7FRDZ
JZu4tAP44DXkv80sE9d38BPOH8l2uijSP5lM6vxAGqClMfmNMVt1rEFy2IE2cgTm
RxEq2Yz+TantdaL7hH9ACQKBgH5g/WickeA9RTrIbFjibpICO4zZhrT/UwrR3hR+
7BtgAF03mFS3IPVeHLhmKx8f6Y+fwLiZXTr0Yep3c5cfmOh2FbtTpw5pcBv4lGeh
hCR1aoO2r0PF1lYxEdDuWaLH0E8+1KiAyJ9tKdj7mVtQqdW9Y5BcRZKpHNQrO0r6
jE/DAoGBAJsenpyefbzYLlp2QJUBO23C0JxF9tcIzHfRVbjUckElxBJE4tPphyzm
WNzQ+rR5w72QeRk5Qh82+ZeuUnZlx0JZ31wFaREqE4j4EbtJurBNNaXIm7E/cFJ8
xG8Eiz7OOeI20NeKd3EcvEZ5hTHZKFRKyCSteRB4eWvjbvEeaPJR
-----END RSA PRIVATE KEY-----\n"""

print openssl == keyfactory.parsePEMKey(openssl).write()

crypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, "rsa"))
print "Primary RSA", crypter.Encrypt(input)  # primary
activeRsa = crypter.GetKey("zmM4uw")  # active
print "Active RSA", util.Encode(activeRsa.Encrypt(input))

print "Testing RSA..."
rsa_key = keys.RsaPrivateKey.Generate()
ciph = rsa_key.Encrypt("hello")
print rsa_key.Decrypt(ciph)
sig = rsa_key.Sign("Hi Google")
print rsa_key.Verify("Hi Google", sig)