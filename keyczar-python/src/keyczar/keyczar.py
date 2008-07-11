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

__author__ = """steveweis@gmail.com (Steve Weis), 
                arkajit.dey@gmail.com (Arkajit Dey)"""

import readers
import keydata
import keyinfo
import keys
import errors
import util

from Crypto.Cipher import AES

VERSION = 1
FORMAT = 1
KEY_HASH_SIZE = 4
HEADER_SIZE = 2 + KEY_HASH_SIZE

class Keyczar(object):
  
  """Abstract Keyczar base class."""
    
  def __init__(self, reader):
    self.metadata = keydata.KeyMetadata.Read(reader.GetMetadata())
    self.__keys = {}  # maps both KeyVersions and hash ids to keys
    self.primary_version = None  # default if no primary key
    self.default_size = self.metadata.type.default_size
    
    if not self.IsAcceptablePurpose(self.metadata.purpose):
      raise errors.KeyczarError("Unacceptable purpose: %s" 
                                % self.metadata.purpose)
      
    for version in self.metadata.versions:
      if version.status == keyinfo.PRIMARY:
        if self.primary_version is not None:
          raise errors.KeyczarError(
              "Key sets may only have a single primary version")
        self.primary_version = version
      key = keys.ReadKey(self.metadata.type, 
                         reader.GetKey(version.version_number))
      self.__keys[version] = key
      self.__keys[key.hash] = key
    
  versions = property(lambda self: [k for k in self.__keys.keys() 
                                    if isinstance(k, keyinfo.KeyVersion)],
                      doc="""List of versions in key set.""")
  primary_key = property(lambda self: self.GetKey(self.primary_version),
                         doc="""The primary key for this key set.""")
  
  def __str__(self):
    return str(self.metadata)
  
  @staticmethod
  def Read(location):
    """Return a Keyczar object created from FileReader at given location."""
    return Keyczar(readers.FileReader(location))
  
  def IsAcceptablePurpose(self, purpose):
    """Indicates whether purpose is valid. Abstract method."""
  
  def GetKey(self, id):
    """Returns the key associated with the given id, a hash or a version.
    
    Args:
      id: Either the hash identifier of the key or its KeyVersion.
    
    Returns:
      Key: The key associated with this id or None if id doesn't exist.
    """
    return self.__keys.get(id)
  
  def __AddKey(self, version, key):
    self.__keys[version] = self.__keys[key.hash] = key
    self.metadata.AddVersion(version)
  
  def AddVersion(self, status, size=None):
    """Adds a new key version with given status to key set.
    
    Generates a new key of same type (repeated until hash identifier is unique) 
    for this version. Uses supplied key size (if provided) in lieu of the
    default key size. If this is an unacceptable key size, uses the default 
    key size. Uses next available version number.
    
    Args:
      status: a KeyStatus
      size: an integer, size of key in bits. Optional, uses default size
      if not provided.
    
    Raises:
      KeyczarError: If key type unsupported
    """
    if size is None:
      size = self.default_size

    version = keydata.KeyVersion(len(self.versions)+1, status, False)
    
    if status == keyinfo.PRIMARY:
      if self.primary_version is not None:
        self.primary_version.status = keyinfo.ACTIVE
      self.primary_version = version
    
    if size < self.default_size:
      print("WARNING: %d-bit key size is less than recommended default key" +
            "size of %d bits for %s keys."
            % (size, self.default_size, str(self.metadata.type)))
    
    # Make sure no keys collide on their identifiers
    while True:
      key = keys.GenKey(self.metadata.type, size)
      if self.GetKey(key.hash) is None:
        break
    
    self.__AddKey(version, key)
  
  def Promote(self, version_number):
    """Promotes the status of key with given version number.
    
    Promoting ACTIVE key automatically demotes current PRIMARY key to ACTIVE.
    
    Args:
      version_number: integer version number to promote
    
    Raises:
      KeyczarError: If invalid version number or trying to promote a primary key
    """
    version = self.metadata.GetVersion(version_number)
    if version.status == keyinfo.PRIMARY:
      raise errors.KeyczarError("Can't promote a primary key.")
    elif version.status == keyinfo.ACTIVE:
      version.status = keyinfo.PRIMARY
      if self.primary_version is not None:
        self.primary_version.status = keyinfo.ACTIVE  # only one primary key
      self.primary_version = version
    elif version.status == keyinfo.SCHEDULED_FOR_REVOCATION:
      version.status = keyinfo.ACTIVE
  
  def Demote(self, version_number):
    """Demotes the status of key with given version number.
    
    Demoting PRIMARY key results in a key set with no primary version.
    
    Args:
      version_number: integer version number to demote
    
    Raises:
      KeyczarError: If invalid version number or trying to demote a key
          scheduled for revocation. Should use Revoke instead.
    """
    version = self.metadata.GetVersion(version_number)
    if version.status == keyinfo.PRIMARY:
      version.status = keyinfo.ACTIVE
      self.primary_version = None  # no more primary keys in the set
    elif version.status == keyinfo.ACTIVE:
      version.status = keyinfo.SCHEDULED_FOR_REVOCATION
    elif version.status == keyinfo.SCHEDULED_FOR_REVOCATION:
      raise errors.KeyczarError("Can't demote a key scheduled for revocation.")
  
  def Revoke(self, version_number):
    """Revokes the key with given version number if scheduled to be revoked.
    
    Args:
      version_number: integer version number to revoke
    
    Raises:
      KeyczarError: If invalid version number or key is not scheduled
          for revocation.
    """
    version = self.metadata.GetVersion(version_number)
    if version.status == keyinfo.SCHEDULED_FOR_REVOCATION:
      self.metadata.RemoveVersion(version)
    else:
      raise errors.KeyczarError("Can't revoke key if not scheduled to be.")

class GenericKeyczar(Keyczar):
  
  """To be used by Keyczart."""
  
  @staticmethod
  def Read(location):
    """Return a GenericKeyczar created from FileReader at given location."""
    return GenericKeyczar(readers.FileReader(location))

  def IsAcceptablePurpose(self, purpose):
    """All purposes ok for Keyczart."""
    return True
  
  def PublicKeyExport(self, destination):
    """Export the public keys corresponding to our key set to destination."""

class Encrypter(Keyczar):
  
  """Capable of encrypting only."""
  
  @staticmethod
  def Read(location):
    """Return an Encrypter created from FileReader at given location."""
    return Encrypter(readers.FileReader(location))
  
  def IsAcceptablePurpose(self, purpose):
    """Only valid if purpose includes encrypting."""
    return purpose == keyinfo.ENCRYPT or purpose == keyinfo.DECRYPT_AND_ENCRYPT
  
  def CiphertextSize(self, input_length):
    """Return the size of the ciphertext for an input of given length."""
  
  def Encrypt(self, data):
    """Encrypt the data and return the ciphertext.
    
    Parameters:
      data: String message to encrypt
    
    Returns:
      ciphertext encoded as a Base64 string
      
    Raises:
      NoPrimaryKeyError: If no primary key can be found to encrypt.
      KeyczarError: If primary key is not capable of encryption.
    """
    encrypting_key = self.primary_key
    if encrypting_key is None:
      raise errors.NoPrimaryKeyError()
    return util.Encode(encrypting_key.Encrypt(data))
    
class Verifier(Keyczar):
  
  """Capable of verifying only."""
  
  @staticmethod
  def Read(location):
    """Return a Verifier created from FileReader at given location."""
    return Verifier(readers.FileReader(location))
  
  def IsAcceptablePurpose(self, purpose):
    """Only valid if purpose includes verifying."""
    return purpose == keyinfo.VERIFY or purpose == keyinfo.SIGN_AND_VERIFY
  
  def Verify(self, data, sig):
    """Verifies whether the signature corresponds to the given data.
    
    Args:
      data:
      sig:
    
    Returns:
      True if sig corresponds to data, False otherwise.
    """

class Crypter(Encrypter):
  
  """Capable of encrypting and decrypting."""
  
  @staticmethod
  def Read(location):
    """Return a Crypter created from FileReader at given location."""
    return Crypter(readers.FileReader(location))
  
  def IsAcceptablePurpose(self, purpose):
    """Only valid if purpose includes decrypting"""
    return purpose == keyinfo.DECRYPT_AND_ENCRYPT
  
  def Decrypt(self, ciphertext):
    """Decrypts the given ciphertext and returns the plaintext.
    
    Parameters:
      ciphertext: Base64 encoded string ciphertext to be decrypted.
      
    Returns:
      Plaintext String message
    
    Raises:
      ShortCiphertextError: If length is too short to have Header, IV, & Sig.
      BadVersionError: If header specifies an illegal version.
      BadFormatError: If header specifies an illegal format.
      KeyNotFoundError: If key specified in header doesn't exist.
      InvalidSignatureError: If the signature can't be verified. 
    """
    data_bytes = util.Decode(ciphertext)
    if len(data_bytes) < HEADER_SIZE:
      raise errors.ShortCiphertextError(len(data_bytes))
    
    version = ord(data_bytes[0])
    format = ord(data_bytes[1])
    if version != VERSION:
      raise errors.BadVersionError(version)
    if format != FORMAT:
      raise errors.BadFormatError(format)
    
    hash = util.Encode(data_bytes[2:2+KEY_HASH_SIZE])
    key = self.GetKey(hash)
    if key is None:
      raise errors.KeyNotFoundError(hash)
    
    return key.Decrypt(data_bytes)
    
class Signer(Verifier):
  
  """Capable of both signing and verifying."""
  
  @staticmethod
  def Read(location):
    """Return a Signer created from FileReader at given location."""
    return Signer(readers.FileReader(location))
  
  def IsAcceptablePurpose(self, purpose):
    """Only valid if purpose includes signing."""
    return purpose == keyinfo.SIGN_AND_VERIFY
  
  def DigestSize(self):
    """Return the size of signatures produced by this Signer."""
  
  def Sign(self, data):
    """Sign given data and return corresponding signature.
    
    Args:
      data:
    
    Returns:
      Signature on the data.
    """