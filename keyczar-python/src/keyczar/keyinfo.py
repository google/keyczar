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

"""Defines several 'enums' encoding information about keys.

@author: steveweis@gmail.com (Steve Weis) 
@author: arkajit.dey@gmail.com (Arkajit Dey)
"""

class NameId(object):
  def __init__(self, name, id):
    self.name = name
    self.id = id
  
class KeyType(NameId):
  
  """ An 'enum' defining different key types and their properties.

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
    NameId.__init__(name, id)
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
types = {AES.id: AES, HMAC_SHA1.id: HMAC_SHA1, DSA_PRIV.id: DSA_PRIV, 
         DSA_PUB.id: DSA_PUB, RSA_PRIV.id: RSA_PRIV, RSA_PUB.id: RSA_PUB}

def GetType(value):
  if value in types:
    return types[value]
    
class KeyStatus(NameId):
  pass

PRIMARY = KeyStatus("primary", 0)
ACTIVE = KeyStatus("active", 1)
SCHEDULED_FOR_REVOCATION = KeyStatus("scheduled_for_revocation", 2)
statuses = {PRIMARY.id: PRIMARY, ACTIVE.id: ACTIVE, 
            SCHEDULED_FOR_REVOCATION.id: SCHEDULED_FOR_REVOCATION}

def GetStatus(value):
  if value in statuses:
    return statuses[value]

class KeyPurpose(NameId):
  pass

DECRYPT_AND_ENCRYPT = KeyPurpose("crypt", 0)
ENCRYPT = KeyPurpose("encrypt", 1)
SIGN_AND_VERIFY = KeyPurpose("sign", 2)
VERIFY = KeyPurpose("verify", 3)
purposes = {DECRYPT_AND_ENCRYPT.id: DECRYPT_AND_ENCRYPT, ENCRYPT.id: ENCRYPT,
            SIGN_AND_VERIFY.id: SIGN_AND_VERIFY, VERIFY.id: VERIFY}

def GetPurpose(value):
  if value in purposes:
    return purposes[value]
  
class CipherMode(NameId):
  def __init__(self, name, id, useIv, output_size_fn):
    NameId.__init__(name, id)
    self.useIv = useIv
    self.get_output_size = output_size_fn
    
CBC = CipherMode("AES/CBC/PKCS5Padding", 0, True, lambda b, i: (i/b + 2) * b)
CTR = CipherMode("AES/CTR/NoPadding", 1, True, lambda b, i: i + b / 2)
ECB = CipherMode("AES/ECB/NoPadding", 2, False, lambda b, i: b)
DET_CBC = CipherMode("AES/CBC/PKCS5Padding", 3, False, 
                     lambda b, i: (i / b + 1) * b)
modes = {CBC.id: CBC, CTR.id: CTR, ECB.id: ECB, DET_CBC.id: DET_CBC}

def GetMode(value):
  if value in modes:
    return modes[value]
