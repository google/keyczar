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
Collection of all Keyczar classes used to perform cryptographic functions:
encrypt, decrypt, sign and verify.

@author: arkajit.dey@gmail.com (Arkajit Dey)
@author: steveweis@gmail.com (Steve Weis)
"""

import os

from Crypto.Cipher import AES

import errors
import keydata
import keyinfo
import keys
import readers
import util

VERSION = 1
KEY_HASH_SIZE = 4
HEADER_SIZE = 1 + KEY_HASH_SIZE

class Keyczar(object):
  
  """Abstract Keyczar base class."""
    
  def __init__(self, reader):
    self.metadata = keydata.KeyMetadata.Read(reader.GetMetadata())
    self._keys = {}  # maps both KeyVersions and hash ids to keys
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
      key = keys.ReadKey(self.metadata.type, reader.GetKey(version.version_number))
      self._keys[version] = key
      self._keys[key.hash] = key
    
  versions = property(lambda self: [k for k in self._keys.keys() 
                                    if isinstance(k, keydata.KeyVersion)],
                      doc="""List of versions in key set.""")
  primary_key = property(lambda self: self.GetKey(self.primary_version),
                         doc="""The primary key for this key set.""")
  
  def __str__(self):
    return str(self.metadata)
  
  def _ParseHeader(self, header):
    """
    Parse the header and verify version, format info. Return key if exists.
    
    @param header: the bytes of the header of Keyczar output
    @type header: string
      
    @return: the key identified by the hash in the header
    @rtype: L{keys.Key}
    
    @raise BadVersionError: if header specifies an illegal version
    @raise KeyNotFoundError: if key specified in header doesn't exist
    """
    version = ord(header[0])
    if version != VERSION:
      raise errors.BadVersionError(version)
    hash = util.Encode(header[1:])
    return self.GetKey(hash)
  
  @staticmethod
  def Read(location):
    """
    Return a Keyczar object created from FileReader at given location.
    
    @param location: pathname of the directory storing the key files
    @type location: string
    
    @return: a Keyczar to manage the keys stored at the given location
    @rtype: L{Keyczar}
    """
    return Keyczar(readers.FileReader(location))
  
  def IsAcceptablePurpose(self, purpose):
    """Indicates whether purpose is valid. Abstract method."""
  
  def GetKey(self, id):
    """
    Returns the key associated with the given id, a hash or a version.
    
    @param id: Either the hash identifier of the key or its version.
    @type id: string or L{keydata.KeyVersion}
    
    @return: key associated with this id or None if id doesn't exist.
    @rtype: L{keys.Key}
    
    @raise KeyNotFoundError: if key with given id doesn't exist
    """
    try:
      return self._keys[id]
    except KeyError:
      raise errors.KeyNotFoundError(id)
  
  def _AddKey(self, version, key):
    self._keys[version] = self._keys[key.hash] = key
    self.metadata.AddVersion(version)

class GenericKeyczar(Keyczar):
  
  """To be used by Keyczart."""
  
  @staticmethod
  def Read(location):
    """Return a GenericKeyczar created from FileReader at given location."""
    return GenericKeyczar(readers.FileReader(location))

  def IsAcceptablePurpose(self, purpose):
    """All purposes ok for Keyczart."""
    return True
  
  def AddVersion(self, status, size=None):
    """
    Adds a new key version with given status to key set.
    
    Generates a new key of same type (repeated until hash identifier is unique) 
    for this version. Uses supplied key size (if provided) in lieu of the
    default key size. If this is an unacceptable key size, uses the default 
    key size. Uses next available version number.
    
    @param status: the status of the new key to be added
    @type status: L{keyinfo.KeyStatus}
    
    @param size: size of key in bits, uses default size if not provided.
    @type size: integer
    
    @raise KeyczarError: if key type unsupported
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
      if self._keys.get(key.hash) is None:
        break
    
    self._AddKey(version, key)
  
  def Promote(self, version_number):
    """
    Promotes the status of key with given version number.
    
    Promoting ACTIVE key automatically demotes current PRIMARY key to ACTIVE.
    
    @param version_number: the version number to promote
    @type version_number: integer
    
    @raise KeyczarError: if invalid version number or trying to promote 
      a primary key
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
    """
    Demotes the status of key with given version number.
    
    Demoting PRIMARY key results in a key set with no primary version.
    
    @param version_number: the version number to demote
    @type version_number: integer
    
    @raise KeyczarError: if invalid version number or trying to demote a key 
      scheduled for revocation, use L{Revoke} instead.
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
    """
    Revokes the key with given version number if scheduled to be revoked.
    
    @param version_number: integer version number to revoke
    @type version_number: integer
    
    @raise KeyczarError: if invalid version number or key is not scheduled
      for revocation
    """
    version = self.metadata.GetVersion(version_number)
    if version.status == keyinfo.SCHEDULED_FOR_REVOCATION:
      self.metadata.RemoveVersion(version)
    else:
      raise errors.KeyczarError("Can't revoke key if not scheduled to be.")
  
  def PublicKeyExport(self, dest):
    """Export the public keys corresponding to our key set to destination."""
    kmd = self.metadata
    pubkmd = None
    if kmd.type == keyinfo.DSA_PRIV and kmd.purpose == keyinfo.SIGN_AND_VERIFY:
      pubkmd = keydata.KeyMetadata(kmd.name, keyinfo.VERIFY, keyinfo.DSA_PUB)
    elif kmd.type == keyinfo.RSA_PRIV:
      if kmd.purpose == keyinfo.DECRYPT_AND_ENCRYPT:
        pubkmd = keydata.KeyMetadata(kmd.name, keyinfo.ENCRYPT, keyinfo.RSA_PUB)
      elif kmd.purpose == keyinfo.SIGN_AND_VERIFY:
        pubkmd = keydata.KeyMetadata(kmd.name, keyinfo.VERIFY, keyinfo.RSA_PUB)
    if pubkmd is None:
      raise errors.KeyczarError("Cannot export public key")
    util.WriteFile(str(pubkmd), os.path.join(dest, "meta"))
    pubkeys = [self.GetKey(v).public_key for v in self.versions]
    for v in self.versions:
      pubkey = self.GetKey(v).public_key
      util.WriteFile(str(pubkey), os.path.join(dest, v.version_number))
  
  def Write(self, loc):
    util.WriteFile(str(self.metadata), os.path.join(loc, "meta"))
    for v in self.versions:
      util.WriteFile(str(self.GetKey(v)), 
                     os.path.join(loc, str(v.version_number)))

class Encrypter(Keyczar):
  
  """Capable of encrypting only."""
  
  @staticmethod
  def Read(location):
    """
    Return an Encrypter object created from FileReader at given location.
    
    @param location: pathname of the directory storing the key files
    @type location: string
    
    @return: an Encrypter to manage the keys stored at the given location and
      perform encryption functions.
    @rtype: L{Encrypter}
    """
    return Encrypter(readers.FileReader(location))
  
  def IsAcceptablePurpose(self, purpose):
    """Only valid if purpose includes encrypting."""
    return purpose == keyinfo.ENCRYPT or purpose == keyinfo.DECRYPT_AND_ENCRYPT
  
  def Encrypt(self, data):
    """
    Encrypt the data and return the ciphertext.
    
    @param data: message to encrypt
    @type data: string
    
    @return: ciphertext encoded as a Base64 string
    @rtype: string
      
    @raise NoPrimaryKeyError: if no primary key can be found to encrypt
    """
    encrypting_key = self.primary_key
    if encrypting_key is None:
      raise errors.NoPrimaryKeyError()
    return util.Encode(encrypting_key.Encrypt(data))
    
class Verifier(Keyczar):
  
  """Capable of verifying only."""
  
  @staticmethod
  def Read(location):
    """
    Return a Verifier object created from FileReader at given location.
    
    @param location: pathname of the directory storing the key files
    @type location: string
    
    @return: a Verifier to manage the keys stored at the given location and
      perform verify functions.
    @rtype: L{Verifier}
    """
    return Verifier(readers.FileReader(location))
  
  def IsAcceptablePurpose(self, purpose):
    """Only valid if purpose includes verifying."""
    return purpose == keyinfo.VERIFY or purpose == keyinfo.SIGN_AND_VERIFY
  
  def Verify(self, data, sig):
    """
    Verifies whether the signature corresponds to the given data.
    
    @param data: message that has been signed with sig
    @type data: string
    
    @param sig: Base64 string formatted as Header|Signature
    @type sig: string
    
    @return: True if sig corresponds to data, False otherwise.
    @rtype: boolean
    """
    sig_bytes = util.Decode(sig)
    if len(sig_bytes) < HEADER_SIZE:
      raise errors.ShortSignatureError(len(sig_bytes))
    key = self._ParseHeader(sig_bytes[:HEADER_SIZE])
    return key.Verify(sig_bytes[:HEADER_SIZE] + data, sig_bytes[HEADER_SIZE:])

class Crypter(Encrypter):
  
  """Capable of encrypting and decrypting."""

  @staticmethod
  def Read(location):
    """
    Return a Crypter object created from FileReader at given location.
    
    @param location: pathname of the directory storing the key files
    @type location: string
    
    @return: a Crypter to manage the keys stored at the given location and
      perform encryption and decryption functions.
    @rtype: L{Crypter}
    """
    return Crypter(readers.FileReader(location))
  
  def IsAcceptablePurpose(self, purpose):
    """Only valid if purpose includes decrypting"""
    return purpose == keyinfo.DECRYPT_AND_ENCRYPT
  
  def Decrypt(self, ciphertext):
    """
    Decrypts the given ciphertext and returns the plaintext.
    
    @param ciphertext: Base64 encoded string ciphertext to be decrypted.
    @type ciphertext: string
      
    @return: plaintext message
    @rtype: string
    
    @raise ShortCiphertextError: if length is too short to have Header, IV, Sig
    @raise BadVersionError: if header specifies an illegal version
    @raise BadFormatError: if header specifies an illegal format
    @raise KeyNotFoundError: if key specified in header doesn't exist
    @raise InvalidSignatureError: if the signature can't be verified
    """
    data_bytes = util.Decode(ciphertext)
    if len(data_bytes) < HEADER_SIZE:
      raise errors.ShortCiphertextError(len(data_bytes))
    key = self._ParseHeader(data_bytes[:HEADER_SIZE])
    return key.Decrypt(data_bytes)
    
class Signer(Verifier):
  
  """Capable of both signing and verifying."""
  
  @staticmethod
  def Read(location):
    """
    Return a Signer object created from FileReader at given location.
    
    @param location: pathname of the directory storing the key files
    @type location: string
    
    @return: a Signer to manage the keys stored at the given location and
      perform sign and verify functions.
    @rtype: L{Signer}
    """
    return Signer(readers.FileReader(location))
  
  def IsAcceptablePurpose(self, purpose):
    """Only valid if purpose includes signing."""
    return purpose == keyinfo.SIGN_AND_VERIFY
  
  def Sign(self, data):
    """
    Sign given data and return corresponding signature.
    
    For message M, outputs the signature as Header|Sig(Header.M).
    
    @param data: message to be signed
    @type data: string
    
    @return: signature on the data encoded as a Base64 string
    @rtype: string
    """
    signing_key = self.primary_key
    if signing_key is None:
      raise errors.NoPrimaryKeyError()
    header = signing_key.Header()
    return util.Encode(header + signing_key.Sign(header + data))