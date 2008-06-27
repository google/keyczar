from keyczar.KeyczarReader import KeyczarReader
import os

testdata = os.getcwd() + "/../../testdata"
reader = KeyczarReader(testdata + "/aes")
