#!/usr/bin/python2.4
#
# Copyright 2008 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#      http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Script to generate all Java Keyczar keysets and testdata.

@author: arkajit.dey@gmail.com (Arkajit Dey)
@author: steveweis@gmail.com (Steve Weis)
"""

import os

cwd = os.getcwd()

gsonPath = cwd + "/../third_party/gson/gson-1.1.1.jar"
log4jPath = cwd + "/../third_party/log4j/log4j-1.2.15.jar"
binPath = cwd + "/../bin/"
paths = binPath + ":" + gsonPath + ":" + log4jPath
cmd = "java -cp " + paths + " org.keyczar.KeyczarTool"

keyFiles = [("../testdata/aes/", "crypt", None, None),
            ("../testdata/rsa/", "crypt", "rsa", None),
            ("../testdata/aes-crypted/", "crypt", None, "../testdata/aes/"),
            ("../testdata/hmac/", "sign", None, None),
            ("../testdata/dsa/", "sign", "dsa", None),
            ("../testdata/rsa-sign/", "sign", "rsa", None)]

pubKeyFiles = [("../testdata/dsa/", "../testdata/dsa.public/"),
               ("../testdata/rsa-sign/", "../testdata/rsa-sign.public/")]

def cleanUp(directory):
  for file in os.listdir(directory):
    filePath = os.path.join(directory, file)
    if not os.path.isdir(filePath): os.remove(filePath)

def createFlags(loc, name=None, dest=None, purpose=None, status=None, 
                version=None, asymmetric=None, crypter=None):
  flags = " "
  if name is not None: flags += "--name="+name+" "
  if loc is not None: flags += "--location="+loc+" "
  if dest is not None: flags += "--destination="+dest+" "
  if purpose is not None: flags += "--purpose="+purpose+" "
  if status is not None: flags += "--status="+status+" "
  if version is not None: flags += "--version="+version+" "
  if asymmetric is not None: flags += "--asymmetric="+asymmetric+" "
  if crypter is not None: flags += "--crypter="+crypter+" "
  return flags[:-1]

def create(loc, purpose, name=None, asymmetric=None):
  args = createFlags(name=name, loc=loc, purpose=purpose, asymmetric=asymmetric)
  os.chdir(binPath)
  os.system(cmd + " create" + args)

def addKey(loc, status="active", crypter=None):
  args = createFlags(loc=loc, status=status, crypter=crypter)
  os.chdir(binPath)
  os.system(cmd + " addkey" + args)

def pubKey(loc, dest):
  args = createFlags(loc=loc, dest=dest)
  os.chdir(binPath)
  os.system(cmd + " pubkey" + args)

def useKey(loc, dest, crypter, data="This is some test data"):
  args = createFlags(loc=loc, dest=dest, crypter=crypter)
  os.chdir(binPath)
  os.system(cmd + ' usekey "' + data + '"' + args)

#generate private key sets
print "Generating private key sets and golden outputs..."
for (loc, purpose, asymmetric, crypter) in keyFiles:
  print "."
  cleanUp(loc)
  create(name="test", loc=loc, purpose=purpose, asymmetric=asymmetric)
  addKey(loc=loc, status="primary", crypter=crypter)
  useKey(loc=loc, dest=loc+"1.out", crypter=crypter)
  addKey(loc=loc, status="primary", crypter=crypter)
  useKey(loc=loc, dest=loc+"2.out", crypter=crypter)

#export public key sets
print "Exporting public key sets..."
for (loc, dest) in pubKeyFiles:
  print "."
  cleanUp(dest)
  pubKey(loc, dest)

print "Done!"
  