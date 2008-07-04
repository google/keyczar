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

"""Defines several 'enums' encoding information about keys."""

__author__ = """steveweis@gmail.com (Steve Weis), 
                arkajit.dey@gmail.com (Arkajit Dey)"""

class _NameId(object):
  def __init__(self, name, id):
    self.name = name
    self.id = id
  
  def __str__(self):
    return self.name
  
class KeyType(_NameId):
  
  """An 'enum' defining different key types and their properties.

  Defines the following Key Types:
    AES
    HMAC-SHA1
    DSA Private
    DSA Public
    RSA Private
    RSA Public
  """
  
  sizes = property(lambda self: self.__sizes)  # clients can't modify sizes
  
  def __init__(self, name, id, sizes, output_size):
    _NameId.__init__(self, name, id)
    self.__sizes = sizes
    self.output_size = output_size
    self.default_size = self.__sizes[0]

  def __str__(self):
    return self.name
  
  def IsValidSize(self, size):
    return size in self.__sizes

AES = KeyType("AES", 0, [128, 192, 256], 0)
HMAC_SHA1 = KeyType("HMAC-SHA1", 1, [256], 20)
DSA_PRIV = KeyType("DSA Private", 2, [1024], 48)
DSA_PUB = KeyType("DSA Public", 3, [1024], 48)
RSA_PRIV = KeyType("RSA Private", 4, [2048, 1024, 768, 512], 256)
RSA_PUB = KeyType("RSA Public", 4, [2048, 1024, 768, 512], 256)
types = {"AES": AES, "HMAC_SHA1": HMAC_SHA1, "DSA_PRIV": DSA_PRIV, 
         "DSA_PUB": DSA_PUB, "RSA_PRIV": RSA_PRIV, "RSA_PUB": RSA_PUB}

def GetType(name):
  if name in types:
    return types[name]
    
class KeyStatus(_NameId):
  """Encodes the different possible statuses of a key."""

PRIMARY = KeyStatus("primary", 0)
ACTIVE = KeyStatus("active", 1)
SCHEDULED_FOR_REVOCATION = KeyStatus("scheduled_for_revocation", 2)
statuses = {PRIMARY.id: PRIMARY, ACTIVE.id: ACTIVE, 
            SCHEDULED_FOR_REVOCATION.id: SCHEDULED_FOR_REVOCATION}

def GetStatus(value):
  if value in statuses:
    return statuses[value]

class KeyPurpose(_NameId):
  """Encodes the different possible purposes for which a key can be used."""

DECRYPT_AND_ENCRYPT = KeyPurpose("crypt", 0)
ENCRYPT = KeyPurpose("encrypt", 1)
SIGN_AND_VERIFY = KeyPurpose("sign", 2)
VERIFY = KeyPurpose("verify", 3)
purposes = {"DECRYPT_AND_ENCRYPT": DECRYPT_AND_ENCRYPT, "ENCRYPT": ENCRYPT,
            "SIGN_AND_VERIFY": SIGN_AND_VERIFY, "VERIFY": VERIFY}

def GetPurpose(name):
  if name in purposes:
    return purposes[name]
  
class CipherMode(_NameId):
  def __init__(self, name, id, use_iv, OutputSizeFn):
    _NameId.__init__(self, name, id)
    self.use_iv = use_iv
    self.GetOutputSize = OutputSizeFn
    
CBC = CipherMode("AES/CBC/PKCS5Padding", 0, True, lambda b, i: (i/b + 2) * b)
CTR = CipherMode("AES/CTR/NoPadding", 1, True, lambda b, i: i + b / 2)
ECB = CipherMode("AES/ECB/NoPadding", 2, False, lambda b, i: b)
DET_CBC = CipherMode("AES/CBC/PKCS5Padding", 3, False, 
                     lambda b, i: (i / b + 1) * b)
modes = {"CBC": CBC, "CTR": CTR, "ECB": ECB, "DET_CBC": DET_CBC}

def GetMode(name):
  if name in modes:
    return modes[name]