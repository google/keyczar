from keyczar.FileReader import FileReader
import os
import simplejson

testdata = os.getcwd() + "/../testdata"
reader = FileReader(testdata + "/aes")

print reader.GetMetadata()
print reader.GetKey(1)
print reader.GetKey(2)