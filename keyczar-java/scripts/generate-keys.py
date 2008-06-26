#script to generate all keys
import os
#TODO: try jython to access Crypter & Signer
#from com.google.keyczar import Crypter
#from com.google.keyczar import Signer

gsonPath = "/usr/local/google/users/arkajit/eclipse/workspaces/keymaster/" + \
           "Keyczar-Java/third_party/gson/gson.jar"
binPath = "/usr/local/google/users/arkajit/eclipse/workspaces/keymaster/" + \
           "Keyczar-Java/bin/"
paths = binPath + ":" + gsonPath
cmd = "java -cp " + paths + " com.google.keyczar.KeyczarTool"

keyFiles = [("../testdata/aes/", "crypt", None),
            ("../testdata/rsa/", "crypt", "rsa"),
            ("../testdata/hmac/", "sign", None),
            ("../testdata/dsa/", "sign", "dsa"),
            ("../testdata/rsa-sign/", "sign", "rsa")]

pubKeyFiles = [("../testdata/dsa/", "../testdata/dsa.public/"),
               ("../testdata/rsa-sign/", "../testdata/rsa-sign.public/")]

def cleanUp(directory):
  for file in os.listdir(directory):
    filePath = os.path.join(directory, file)
    if not os.path.isdir(filePath): os.remove(filePath)

def createFlags(loc, name=None, dest=None, purpose=None, status=None, 
                version=None, asymmetric=None):
  flags = " "
  if name is not None: flags += "--name="+name+" "
  if loc is not None: flags += "--location="+loc+" "
  if dest is not None: flags += "--destination="+dest+" "
  if purpose is not None: flags += "--purpose="+purpose+" "
  if status is not None: flags += "--status="+status+" "
  if version is not None: flags += "--version="+version+" "
  if asymmetric is not None: flags += "--asymmetric="+asymmetric+" "
  return flags[:-1]

def create(loc, purpose, name=None, asymmetric=None):
  args = createFlags(name=name, loc=loc, purpose=purpose, asymmetric=asymmetric)
  os.chdir(binPath)
  os.system(cmd + " create" + args)

def addKey(loc, status="active"):
  args = createFlags(loc=loc, status=status)
  os.chdir(binPath)
  os.system(cmd + " addkey" + args)

def pubKey(loc, dest):
  args = createFlags(loc=loc, dest=dest)
  os.chdir(binPath)
  os.system(cmd + " pubkey" + args)

#generate private key sets
print "Generating private key sets..."
for (loc, purpose, asymmetric) in keyFiles:
  cleanUp(loc)
  create(name="test", loc=loc, purpose=purpose, asymmetric=asymmetric)
  addKey(loc)
  addKey(loc, "primary")

#export public key sets
print "Exporting public key sets..."
for (loc, dest) in pubKeyFiles:
  cleanUp(dest)
  pubKey(loc, dest)

print "Done!"
  