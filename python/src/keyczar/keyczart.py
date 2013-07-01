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
Keyczart(ool) is a utility for creating and managing Keyczar keysets.

@author: arkajit.dey@gmail.com (Arkajit Dey)
"""

import os
import sys

import errors
import keyczar
import keydata
import keyinfo
import readers
import writers
import util

KEYSETS = [('aes', keyinfo.DECRYPT_AND_ENCRYPT, None, None),
           ('aes-crypted', keyinfo.DECRYPT_AND_ENCRYPT, None, 'aes'),
           ('hmac', keyinfo.SIGN_AND_VERIFY, None, None),
           ('rsa', keyinfo.DECRYPT_AND_ENCRYPT, 'rsa', None),
           ('rsa-sign', keyinfo.SIGN_AND_VERIFY, 'rsa', None),
           ('dsa', keyinfo.SIGN_AND_VERIFY, 'dsa', None)]

mock = None  # mock reader used for testing purposes, disabled when set to None

class _Name(object):
  
  def __init__(self, name):
    self.name = name
  
  def __str__(self):
    return self.name

class Command(_Name):
  """Enum representing keyczart commands."""

CREATE = Command("create")
ADDKEY = Command("addkey")
PUBKEY = Command("pubkey")
PROMOTE = Command("promote")
DEMOTE = Command("demote")
REVOKE = Command("revoke")
GENKEY = Command("genkey")
commands = {"create": CREATE, "addkey": ADDKEY, "pubkey": PUBKEY, 
            "promote": PROMOTE, "demote": DEMOTE, "revoke": REVOKE, 
            "genkey": GENKEY}

def GetCommand(cmd):
  try:
    return commands[cmd]
  except KeyError:
    raise errors.KeyczarError("Illegal command")

class Flag(_Name):
  """Enum representing keyczart flags."""

LOCATION = Flag("location")
NAME = Flag("name")
SIZE = Flag("size")
STATUS = Flag("status")
PURPOSE = Flag("purpose")
DESTINATION = Flag("destination")
VERSION = Flag("version")
ASYMMETRIC = Flag("asymmetric")
CRYPTER = Flag("crypter")
flags = {"location": LOCATION, "name": NAME, "size": SIZE, "status": STATUS,
         "purpose": PURPOSE, "destination": DESTINATION, "version": VERSION,
         "asymmetric": ASYMMETRIC, "crypter": CRYPTER}

def GetFlag(flag):
  try:
    return flags[flag]
  except KeyError:
    raise errors.KeyczarError("Unknown flag")

def Create(loc, name, purpose, asymmetric=None):
  if mock is None and loc is None:  # not testing
    raise errors.KeyczarError("Location missing")
  
  kmd = None
  if purpose == keyinfo.SIGN_AND_VERIFY:
    if asymmetric is None:
      kmd = keydata.KeyMetadata(name, purpose, keyinfo.HMAC_SHA1)
    elif asymmetric.lower() == "rsa":
      kmd = keydata.KeyMetadata(name, purpose, keyinfo.RSA_PRIV)
    else:  # default to DSA
      kmd = keydata.KeyMetadata(name, purpose, keyinfo.DSA_PRIV)
  elif purpose == keyinfo.DECRYPT_AND_ENCRYPT:
    if asymmetric is None:
      kmd = keydata.KeyMetadata(name, purpose, keyinfo.AES)
    else:  # default to RSA
      kmd = keydata.KeyMetadata(name, purpose, keyinfo.RSA_PRIV)
  else:
    raise errors.KeyczarError("Missing or unsupported purpose")
  
  if mock is not None:  # just testing, update mock object
    mock.kmd = kmd
  else:
    writer = writers.CreateWriter(loc)
    try:
      writer.WriteMetadata(kmd, overwrite=False)
    finally:
      writer.Close()

def AddKey(loc, status, crypter=None, size=None):
  czar = CreateGenericKeyczar(loc, crypter)
  if size == -1:
    size = None
  czar.AddVersion(status, size)
  UpdateGenericKeyczar(czar, loc, crypter)

def PubKey(loc, dest):
  if mock is None and dest is None:  # not required when testing
    raise errors.KeyczarError("Must define destination")
  czar = CreateGenericKeyczar(loc)
  czar.PublicKeyExport(dest, mock)  # supply mock for testing if enabled

def Promote(loc, num):
  czar = CreateGenericKeyczar(loc)
  if num < 0:
    raise errors.KeyczarError("Missing version")
  czar.Promote(num)
  UpdateGenericKeyczar(czar, loc)
  
def Demote(loc, num):
  czar = CreateGenericKeyczar(loc)
  if num < 0:
    raise errors.KeyczarError("Missing version")
  czar.Demote(num)
  UpdateGenericKeyczar(czar, loc)

def Revoke(loc, num):
  czar = CreateGenericKeyczar(loc)
  if num < 0:
    raise errors.KeyczarError("Missing version")
  czar.Revoke(num)
  UpdateGenericKeyczar(czar, loc)
  if mock is not None:  # testing, update mock
    mock.RemoveKey(num)
  else:
    writer = writers.CreateWriter(loc)
    try:
      writer.Remove(num)
    finally:
      writer.Close()

def _CreateCrypter(location):
  """Helper to create a Crypter for the location."""
  return keyczar.Crypter.Read(location)

def GenKeySet(loc):
  print "Generating private key sets..."
  for (name, purpose, asymmetric, crypter) in KEYSETS:
    print "."
    dir_path = os.path.join(loc, name)
    if crypter:
      crypter = _CreateCrypter(os.path.join(loc, crypter))
    Clean(dir_path)
    Create(dir_path, "Test", purpose, asymmetric)
    AddKey(dir_path, keyinfo.PRIMARY, crypter)
    UseKey(purpose, dir_path, os.path.join(dir_path, "1.out"), crypter)
    AddKey(dir_path, keyinfo.PRIMARY, crypter)
    UseKey(purpose, dir_path, os.path.join(dir_path, "2.out"), crypter)
  
  print "Exporting public key sets..."
  for name in ('dsa', 'rsa-sign'):
    print "."
    dir_path = os.path.join(loc, name)
    dest = os.path.join(loc, name + '.public')
    PubKey(dir_path, dest)
  print "Done!"

def Clean(directory):
  for filename in os.listdir(directory):
    path = os.path.join(directory, filename)
    if not os.path.isdir(path): 
      os.remove(path)

def UseKey(purpose, loc, dest, crypter=None, msg="This is some test data"):
  reader = readers.CreateReader(loc)
  try:
    answer = ""
    if crypter:
      reader = readers.EncryptedReader(reader, crypter)
    if purpose == keyinfo.DECRYPT_AND_ENCRYPT:
      answer = keyczar.Crypter(reader).Encrypt(msg)
    elif purpose == keyinfo.SIGN_AND_VERIFY:
      answer = keyczar.Signer(reader).Sign(msg)
    util.WriteFile(answer, dest)
  finally:
    reader.Close()

def Usage():
  print '''Usage: "keyczart command flags"
  Commands: create addkey pubkey promote demote revoke
Flags: location name size status purpose destination version asymmetric crypter
Command Usage:
create --location=/path/to/keys --purpose=(crypt|sign) [--name="A name"] [--asymmetric=(dsa|rsa)]
  Creates a new, empty key set in the given location.
  This key set must have a purpose of either "crypt" or "sign"
  and may optionally be given a name. The optional asymmetric 
  flag will generate a public key set of the given algorithm.
  The "dsa" asymmetric value is valid only for sets with "sign" purpose.
  with the given purpose.
addkey --location=/path/to/keys [--status=(active|primary)] [--size=size] [--crypter=crypterLocation]
  Adds a new key to an existing key set. Optionally
  specify a purpose, which is active by default. Optionally
  specify a key size in bits. Also optionally specify the
  location of a set of crypting keys, which will be used to
  encrypt this key set.
pubkey --location=/path/to/keys --destination=/destination
  Extracts public keys from a given key set and writes them
  to the destination. The "pubkey" command Only works for
  key sets that were created with the "--asymmetric" flag.
promote --location=/path/to/keys --version=versionNumber
  Promotes the status of the given key version in the given 
  location. Active keys are promoted to primary (which demotes 
  any existing primary key to active). Keys scheduled for 
  revocation are promoted to be active.
demote --location=/path/to/keys --version=versionNumber
  Demotes the status of the given key version in the given
  location. Primary keys are demoted to active. Active keys
  are scheduled for revocation.
revoke --location=/path/to/keys --version=versionNumber
  Revokes the key of the given version number.
  This key must have been scheduled for revocation by the
  promote command. WARNING: The key will be destroyed.

Optional flags are in [brackets]. The notation (a|b|c) means "a", "b", and "c"
are the valid choices'''

def CreateGenericKeyczar(loc, crypter=None):
  if mock is not None:
    return keyczar.GenericKeyczar(mock)
  if loc is None:
    raise errors.KeyczarError("Need location")
  else:
    generic = None
    reader = readers.CreateReader(loc)
    try:
      if crypter:
        reader = readers.EncryptedReader(reader, crypter)
      generic = keyczar.GenericKeyczar(reader)
    finally:
      reader.Close()
    return generic

def UpdateGenericKeyczar(czar, loc, encrypter=None):
  if mock is not None:  # update key data
    mock.kmd = czar.metadata
    for v in czar.versions:
      mock.SetKey(v.version_number, czar.GetKey(v))
  else:
    writer = writers.CreateWriter(loc)
    try:
      czar.Write(writer, encrypter)
    finally:
      writer.Close()

# Used when called as the keyczar command-line tool (created by setuptools)
def _main_setuptools():
  return main(sys.argv[1:])

def main(argv):
  if len(argv) == 0:
    Usage()
  else:
    cmd = GetCommand(argv[0])   
    flags = {}
    for arg in argv:
      if arg.startswith("--"):
        arg = arg[2:]  # trim leading dashes
        try:
          [flag, val] = arg.split("=")
          flags[GetFlag(flag)] = val
        except ValueError:
          print "Flags incorrectly formatted"
          Usage()
    
    try:
      version = int(flags.get(VERSION, -1))
      size = int(flags.get(SIZE, -1))
      # -1 if non-existent
    except ValueError:
      print "Size and version flags require an integer"
      Usage()
    
    loc = flags.get(LOCATION)  # all commands need location
    
    if cmd == CREATE:
      purpose = {'crypt': keyinfo.DECRYPT_AND_ENCRYPT,
                 'sign': keyinfo.SIGN_AND_VERIFY}.get(flags.get(PURPOSE))
      Create(loc, flags.get(NAME, 'Test'), purpose, flags.get(ASYMMETRIC))
    elif cmd == ADDKEY:
      status = keyinfo.GetStatus(flags.get(STATUS, 'ACTIVE').upper())
      if CRYPTER in flags:
        crypter = _CreateCrypter(flags[CRYPTER])
      else:
        crypter = None
      AddKey(loc, status, crypter, size)
    elif cmd == PUBKEY:
      PubKey(loc, flags.get(DESTINATION))
    elif cmd == PROMOTE:
      Promote(loc, version)
    elif cmd == DEMOTE:
      Demote(loc, version)
    elif cmd == REVOKE:
      Revoke(loc, version)
    elif cmd == GENKEY:
      GenKeySet(loc)
    else:
      Usage()

if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))  # sys.argv[0] is name of program
