from keyczar import readers
from keyczar import keyczar
from keyczar import keyinfo
import os
import simplejson

#FIXME: can't read from readers until hash format is changed from list of
#integers to byte string

#testdata = os.getcwd() + "/../../testdata"
#reader = readers.FileReader(testdata + "/aes")
#kc = keyczar.GenericKeyczar(reader)