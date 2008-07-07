from keyczar import readers
from keyczar import keyczar
from keyczar import keyinfo
import os
import simplejson

print isinstance(keyinfo.AES, keyinfo.KeyType)
print keyinfo.AES.default_size

#FIXME: key.type is not getting initialized properly as keyinfo.AES

testdata = os.getcwd() + "/../../testdata"
reader = readers.FileReader(testdata + "/aes")
kc = keyczar.GenericKeyczar(reader)

print reader.GetMetadata()
print kc.GetKey(1)
print kc.GetKey(2)