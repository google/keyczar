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
USEKEY = Command("usekey")
commands = {"create": CREATE, "addkey": ADDKEY, "pubkey": PUBKEY, 
            "promote": PROMOTE, "demote": DEMOTE, "revoke": REVOKE, 
            "usekey": USEKEY}

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

def Create(loc, name, purpose, asymmetric):
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
  meta = open(os.path.join(loc, "meta"), "w")
  if os.path.exists(meta):
    raise errors.KeyczarError("File already exists")
  try:
    meta.write(str(kmd))
  except IOError:
    raise errors.KeyczarError("Unable to write")

def AddKey(loc, status, size):
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

def UseKey(msg, loc, dest):
  pass

def Usage():
  print "Usage: "

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
      Create(flags.get(LOCATION), flags.get(NAME, ''), flags.get(PURPOSE), 
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
    elif cmd == USEKEY and len(argv) > 2:
      UseKey(argv[1], flags.get(LOCATION), flags.get(DESTINATION))
    else:
      Usage()

if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))  # sys.argv[0] is name of program