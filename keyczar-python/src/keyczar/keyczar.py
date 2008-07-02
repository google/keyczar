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
import errors

class Keyczar(object):
  
  """Abstract Keyczar base class."""
    
  def __init__(self, reader):
    self.metadata = reader.GetMetadata()
    self.keys = {}  # maps both KeyVersions and hash ids to keys
    self.primary_version = None
    
    if not self.IsAcceptablePurpose(self.metadata.purpose):
      raise errors.KeyczarError("Unacceptable purpose: " + 
                                self.metadata.purpose)
      
    for version in self.metadata.versions:
      if version.status == keyinfo.PRIMARY:
        if self.primary_version is not None:
          raise errors.KeyczarError(
              "Key sets may only have a single primary version")
        self.primary_version = version
      key = reader.GetKey(version.version_number)
      self.keys[version] = self.keys[key.hash] = key
    
  versions = property(lambda self: [k for k in self.keys.keys() 
                                    if isinstance(k, keyinfo.KeyVersion)],
                      doc="""List of versions in key set.""")
  
  def __str__(self):
    return str(self.metadata)
  
  @staticmethod
  def Read(location):
    """Return a Keyczar object created from FileReader at given location."""
    return Keyczar(readers.FileReader(location))
  
  def IsAcceptablePurpose(self, purpose):
    """Indicates whether purpose is valid. Abstract method."""
  
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
  
  def Promote(self, version_number):
    """Promotes the status of key with given version number.
    
    Promoting ACTIVE key automatically demotes current PRIMARY key to ACTIVE.
    
    Args:
      version_number: integer version number to promote
    
    Raises:
      KeyczarError: If invalid version number or trying to promote a primary key
    """
  
  def Demote(self, version_number):
    """Demotes the status of key with given version number.
    
    Demoting PRIMARY key results in a key set with no primary version.
    
    Args:
      version_number: integer version number to demote
    
    Raises:
      KeyczarError: If invalid version number or trying to demote a key
          scheduled for revocation. Should use Revoke instead.
    """
  
  def Revoke(self, version_number):
    """Revokes the key with given version number if scheduled to be revoked.
    
    Args:
      version_number: integer version number to revoke
    
    Raises:
      KeyczarError: If invalid version number or key is not scheduled
          for revocation.
    """

class GenericKeyczar(Keyczar):
  pass

class Encrypter(Keyczar):
  pass

class Verifier(Keyczar):
  pass

class Crypter(Encrypter):
  pass

class Signer(Verifier):
  pass


