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
Defines several 'enums' encoding information about keys, such as type,
status, purpose, and the cipher mode.

@author: arkajit.dey@gmail.com (Arkajit Dey)
"""

import errors

class _NameId(object):
  def __init__(self, name, key_id):
    self.name = name
    self.id = key_id

  def __str__(self):
    return self.name

class KeyType(_NameId):
  """
  Encodes different key types and their properties:
    - AES
    - HMAC-SHA1
    - DSA Private
    - DSA Public
    - RSA Private
    - RSA Public
  """

  sizes = property(lambda self: self.__sizes,
                   doc="""List of valid key sizes for this key type.""")
  # clients can't modify sizes

  def __init__(self, name, key_id, sizes, output_size):
    _NameId.__init__(self, name, key_id)
    self.__sizes = sizes
    self.output_size = output_size
    self.default_size = self.__sizes[0]

  def IsValidSize(self, size):
    return size in self.__sizes

AES = KeyType("AES", 0, [128, 192, 256], 0)
HMAC_SHA1 = KeyType("HMAC_SHA1", 1, [256], 20)
DSA_PRIV = KeyType("DSA_PRIV", 2, [1024], 48)
DSA_PUB = KeyType("DSA_PUB", 3, [1024], 48)
RSA_PRIV = KeyType("RSA_PRIV", 4, [2048, 4096, 1024, 768, 512], 256)
RSA_PUB = KeyType("RSA_PUB", 4, [2048, 4096, 1024, 768, 512], 256)
types = {"AES": AES, "HMAC_SHA1": HMAC_SHA1, "DSA_PRIV": DSA_PRIV,
         "DSA_PUB": DSA_PUB, "RSA_PRIV": RSA_PRIV, "RSA_PUB": RSA_PUB}

def GetType(name):
  try:
    return types[name]
  except KeyError:
    raise errors.KeyczarError("Invalid Key Type")

class KeyStatus(_NameId):
  """
  Encodes the different possible statuses of a key:
    - Primary: can be used to encrypt and sign new data
    - Active: can be used to decrypt or verify data signed previously
    - Inactive: can do the same functions as an active key, but about
      to be revoked
  """

PRIMARY = KeyStatus("PRIMARY", 0)
ACTIVE = KeyStatus("ACTIVE", 1)
INACTIVE = KeyStatus("INACTIVE", 2)
statuses = {"PRIMARY": PRIMARY, "ACTIVE": ACTIVE, "INACTIVE": INACTIVE}

def GetStatus(value):
  try:
    return statuses[value]
  except KeyError:
    raise errors.KeyczarError("Invalid Key Status")

class KeyPurpose(_NameId):
  """
  Encodes the different possible purposes for which a key can be used:
    - Decrypt and Encrypt
    - Encrypt (only)
    - Sign and Verify
    - Verify (only)
  """

DECRYPT_AND_ENCRYPT = KeyPurpose("DECRYPT_AND_ENCRYPT", 0)
ENCRYPT = KeyPurpose("ENCRYPT", 1)
SIGN_AND_VERIFY = KeyPurpose("SIGN_AND_VERIFY", 2)
VERIFY = KeyPurpose("VERIFY", 3)
purposes = {"DECRYPT_AND_ENCRYPT": DECRYPT_AND_ENCRYPT, "ENCRYPT": ENCRYPT,
            "SIGN_AND_VERIFY": SIGN_AND_VERIFY, "VERIFY": VERIFY}

def GetPurpose(name):
  try:
    return purposes[name]
  except KeyError:
    raise errors.KeyczarError("Invalid Key Purpose")

class CipherMode(_NameId):
  """
  Encodes the different possible modes for a cipher:
    - Cipher Block Chaining (CBC)
    - Counter (CTR)
    - Electronic Code Book (ECB)
    - Cipher Block Chaining without IV (DET-CBC)
  """

  def __init__(self, name, key_id, use_iv, OutputSizeFn):
    _NameId.__init__(self, name, key_id)
    self.use_iv = use_iv
    self.GetOutputSize = OutputSizeFn

CBC = CipherMode("CBC", 0, True, lambda b, i: (i / b + 2) * b)
CTR = CipherMode("CTR", 1, True, lambda b, i: i + b / 2)
ECB = CipherMode("ECB", 2, False, lambda b, i: b)
DET_CBC = CipherMode("DET_CBC", 3, False, lambda b, i: (i / b + 1) * b)
modes = {"CBC": CBC, "CTR": CTR, "ECB": ECB, "DET_CBC": DET_CBC}

def GetMode(name):
  try:
    return modes[name]
  except KeyError:
    raise errors.KeyczarError("Invalid Cipher Mode")
