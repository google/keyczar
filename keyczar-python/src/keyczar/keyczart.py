#!/usr/bin/python2.4
#
# Copyright 2008 Google Inc. All Rights Reserved.
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
import util

KEYSETS = [('aes', keyinfo.DECRYPT_AND_ENCRYPT, None),
           ('hmac', keyinfo.SIGN_AND_VERIFY, None),
           ('rsa', keyinfo.DECRYPT_AND_ENCRYPT, 'rsa'),
           ('rsa-sign', keyinfo.SIGN_AND_VERIFY, 'rsa'),
           ('dsa', keyinfo.SIGN_AND_VERIFY, 'dsa')]

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
flags = {"location": LOCATION, "name": NAME, "size": SIZE, "status": STATUS,
         "purpose": PURPOSE, "destination": DESTINATION, "version": VERSION,
         "asymmetric": ASYMMETRIC}

def GetFlag(flag):
  try:
    return flags[flag]
  except KeyError:
    raise errors.KeyczarError("Unknown flag")

def Create(loc, name, purpose, asymmetric=None):
  if loc is None:
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
  name = os.path.join(loc, "meta")
  if os.path.exists(name):
    raise errors.KeyczarError("File already exists")
  meta = open(name, "w")
  try:
    meta.write(str(kmd))
  except IOError:
    raise errors.KeyczarError("Unable to write")

def AddKey(loc, status, size=None):
  czar = CreateGenericKeyczar(loc)
  if size == -1:
    size = None
  czar.AddVersion(status, size)
  UpdateGenericKeyczar(czar, loc)

def PubKey(loc, dest):
  if dest is None:
    raise errors.KeyczarError("Must define destination")
  czar = CreateGenericKeyczar(loc)
  czar.PublicKeyExport(dest)

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

def GenKeySet(loc):
  print "Generating private key sets..."
  for (name, purpose, asymmetric) in KEYSETS:
    print "."
    dir = os.path.join(loc, name)
    Clean(dir)
    Create(dir, "Test", purpose, asymmetric)
    AddKey(dir, keyinfo.PRIMARY)
    UseKey(purpose, dir, os.path.join(dir, "1out"))
    AddKey(dir, keyinfo.PRIMARY)
    UseKey(purpose, dir, os.path.join(dir, "2out"))
  
  print "Exporting public key sets..."
  for name in ('dsa', 'rsa-sign'):
    print "."
    dir = os.path.join(loc, name)
    dest = os.path.join(loc, name + '.public')
    PubKey(dir, dest)

def Clean(directory):
  for file in os.listdir(directory):
    path = os.path.join(directory, file)
    if not os.path.isdir(path): 
      os.remove(path)

def UseKey(purpose, loc, dest, msg="Hello Google"):
  if purpose == keyinfo.DECRYPT_AND_ENCRYPT:
    crypter = keyczar.Crypter.Read(loc)
    util.WriteFile(crypter.Encrypt(msg), dest)
  elif purpose == keyinfo.SIGN_AND_VERIFY:
    signer = keyczar.Signer.Read(loc)
    util.WriteFile(signer.Sign(msg), dest)

def Usage():
  print '''Usage: "Keyczart command flags"
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

def CreateGenericKeyczar(loc):
  if loc is None:
    raise errors.KeyczarError("Need location")
  else:
    return keyczar.GenericKeyczar.Read(loc)

def UpdateGenericKeyczar(czar, loc):
  czar.Write(loc)

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
          Usage()
    if cmd == CREATE:
      purpose = {'crypt': keyinfo.DECRYPT_AND_ENCRYPT,
                 'sign': keyinfo.SIGN_AND_VERIFY}.get(flags.get(PURPOSE))
      Create(flags.get(LOCATION), flags.get(NAME, 'Test'), purpose, 
             flags.get(ASYMMETRIC))
    elif cmd == ADDKEY:
      AddKey(flags.get(LOCATION), 
             keyinfo.GetStatus(flags.get(STATUS, 'ACTIVE')), 
             int(flags.get(SIZE, -1)))
    elif cmd == PUBKEY:
      PubKey(flags.get(LOCATION), flags.get(DESTINATION))
    elif cmd == PROMOTE:
      Promote(flags.get(LOCATION), int(flags.get(VERSION, -1)))
    elif cmd == DEMOTE:
      Demote(flags.get(LOCATION), int(flags.get(VERSION, -1)))
    elif cmd == REVOKE:
      Revoke(flags.get(LOCATION), int(flags.get(VERSION, -1)))
    elif cmd == GENKEY:
      GenKeySet(flags.get(LOCATION))
    else:
      Usage()

if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))  # sys.argv[0] is name of program