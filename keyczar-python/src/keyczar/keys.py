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

"""Represents cryptographic keys in Keyczar.

Identifies a key by its hash and type. Includes several subclasses
of base class Key.
"""

__author__ = """steveweis@gmail.com (Steve Weis), 
                arkajit.dey@gmail.com (Arkajit Dey)"""

import errors
import keyinfo
import util

import simplejson

import base64

class Key(object):
  
  """Parent class for Keyczar Keys."""
  
  def __init__(self, type, hash):
    self.type = type
    self.hash = hash
    self.__size = self.type.default_size  # initially default
    
  def __str__(self):
    return "(%s %s %s)" % (self.type, self.hash, self.key_string)
  
  def __SetSize(self, new_size):
    if self.type.IsValidSize(new_size):
      self.__size = new_size
  
  def _GetKeyString(self):
    """Return the key as a string. Abstract method."""
  
  def __GetKeyString(self):
    """Return the key as a string."""
    return self._GetKeyString()  # indirection allows subclass overriding
  
  size = property(lambda self: self.__size, __SetSize, 
                  doc="""The size of the key in bits.""")
  
  key_string = property(__GetKeyString, doc="""The key as a string.""")

class SymmetricKey(Key):
  
  """Parent class for symmetric keys such as AES, HMAC-SHA1"""
  
  def __init__(self, type, hash, key_string):
    Key.__init__(self, type, hash)
    self.__key_string = key_string
  
  def _GetKeyString(self):
    """Return the key as a string."""
    return self.__key_string

def GenKey(type, size=None):
  if size is None:
    size = type.default_size
  try:
    return {keyinfo.AES: AesKey.Generate,
            keyinfo.HMAC_SHA1: HmacKey.Generate,
            keyinfo.DSA_PRIV: DsaPrivateKey.Generate,
            keyinfo.RSA_PRIV: RsaPrivateKey.Generate}[type](size)
  except KeyError:
    if type == keyinfo.DSA_PUB or type == keyinfo.RSA_PUB:
      msg = "Public keys of type %s must be exported from private keys."
    else:
      msg = "Unsupported key type: %s"
    raise errors.KeyczarError(msg % type)

def ReadKey(type, key):
  try:
    return {keyinfo.AES: AesKey.Read,
            keyinfo.HMAC_SHA1: HmacKey.Read,
            keyinfo.DSA_PRIV: DsaPrivateKey.Read,
            keyinfo.RSA_PRIV: RsaPrivateKey.Read,
            keyinfo.DSA_PUB: DsaPublicKey.Read,
            keyinfo.RSA_PUB: RsaPublicKey.Read}[type](key)
  except KeyError:
    raise errors.KeyczarError("Unsupported key type: %s" % type)

class AesKey(SymmetricKey):
  
  def __init__(self, hash, key_string):
    SymmetricKey.__init__(self, keyinfo.AES, hash, key_string)
    self.mode = keyinfo.CBC
    self.hmac_key = None  # generate one upon creation
    self.block_size = len(base64.urlsafe_b64decode(key_string))
  
  @staticmethod
  def Generate(size=None):
    if size is None:
      size = keyinfo.AES.default_size
    
    key_bytes = util.RandBytes(size / 8)
    key_string = base64.urlsafe_b64encode(key_bytes)
    hmac_key = HmacKey.Generate()  # use default HMAC-SHA1 key size
    full_hash = util.Hash([util.IntToBytes(len(key_bytes)), key_bytes, 
                           base64.urlsafe_b64decode(hmac_key.hash)])
    hash = base64.urlsafe_b64encode(full_hash[:4])  # first 4 bytes only
    
    key = AesKey(hash, key_string)
    key.hmac_key = hmac_key
    key.size = size
    return key
  
  @staticmethod
  def Read(key):
    aes = simplejson.loads(key)
    aes_key = AesKey(aes['hash'], aes['aesKeyString'])
    hmac = aes['hmacKey']
    aes_key.hmac_key = HmacKey(hmac['hash'], hmac['hmacKeyString'])
    aes_key.mode = keyinfo.GetMode(aes['mode'])
    return aes_key
    

class HmacKey(SymmetricKey):
  
  def __init__(self, hash, key_string):
    SymmetricKey.__init__(self, keyinfo.HMAC_SHA1, hash, key_string)
  
  @staticmethod
  def Generate(size=None):
    if size is None:
      size = keyinfo.HMAC_SHA1.default_size
    
    key_bytes = util.RandBytes(size / 8)
    key_string = base64.urlsafe_b64encode(key_bytes)
    full_hash = util.Hash([util.IntToBytes(len(key_bytes)), key_bytes])
    hash = base64.urlsafe_b64encode(full_hash[:4])  # first 4 bytes only
    
    key = HmacKey(hash, key_string)
    key.size = size
    return key
  
  @staticmethod
  def Read(key):
    hmac = simplejson.loads(key)
    return HmacKey(hmac['hash'], hmac['hmacKeyString'])

class PrivateKey(Key):
  
  """Represents private keys in Keyczar for asymmetric key pairs."""
  
  def __init__(self, type, hash, pkcs8):
    Key.__init__(type, hash)
    self.pkcs8 = pkcs8
    
  def GetPublic(self):
    pass
  
  def SetPublic(self):
    pass
  
  def _GetKeyString(self):
    return self.pkcs8

class PublicKey(Key):
  
  """Represents public keys in Keyczar for asymmetric key pairs."""
  
  def __init__(self, type, hash, x509):
    Key.__init__(type, hash)
    self.x509 = x509
  
  def _GetKeyString(self):
    return self.x509

class DsaPrivateKey(PrivateKey):
  
  @staticmethod
  def Generate(size=None):
    pass
  
  @staticmethod
  def Read(key):
    pass

class RsaPrivateKey(PrivateKey):
  
  @staticmethod
  def Generate(size=None):
    pass
  
  @staticmethod
  def Read(key):
    pass

class DsaPublicKey(PublicKey):
  
  @staticmethod
  def Read(key):
    pass

class RsaPublicKey(PublicKey):
  
  @staticmethod
  def Read(key):
    pass