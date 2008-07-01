from keyczar import readers
import os
import simplejson

testdata = os.getcwd() + "/../testdata"
reader = readers.FileReader(testdata + "/aes")

print reader.GetMetadata()
print reader.GetKey(1)
print reader.GetKey(2)