from keyczar.FileReader import FileReader
import os
import simplejson

testdata = os.getcwd() + "/../testdata"
reader = FileReader(testdata + "/aes")

print reader.metadata()
print reader.key(1)
print reader.key(2)