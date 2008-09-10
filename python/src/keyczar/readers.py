#!/usr/bin/python2.4
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
A Reader supports reading metadata and key info for key sets.

@author: arkajit.dey@gmail.com (Arkajit Dey)
"""

import os                

import errors
import keydata
import keys
import util

class Reader(object):
  """Interface providing supported methods (no implementation)."""

  def GetMetadata(self):
    """
    Return the KeyMetadata for the key set being read.
    
    @return: JSON string representation of KeyMetadata object
    @rtype: string
    
    @raise KeyczarError: if unable to read metadata (e.g. IOError) 
    """
  
  def GetKey(self, version_number):
    """
    Return the key corresponding to the given version.
    
    @param version_number: the version number of the desired key
    @type version_number: integer
    
    @return: JSON string representation of a Key object
    @rtype: string
    
    @raise KeyczarError: if unable to read key info (e.g. IOError) 
    """

class FileReader(Reader):
  """Reader that reads key data from files."""
  
  def __init__(self, location):
    self._location = location
    
  def GetMetadata(self):
    return util.ReadFile(os.path.join(self._location, "meta"))

  def GetKey(self, version_number):
    return util.ReadFile(os.path.join(self._location, str(version_number)))

class EncryptedReader(Reader):
  """Reader that reads encrypted key data from files."""
  
  def __init__(self, reader, crypter):
    self._reader = reader
    self._crypter = crypter
  
  def GetMetadata(self):
    return self._reader.GetMetadata()
  
  def GetKey(self, version_number):
    return self._crypter.Decrypt(self._reader.GetKey(version_number))

class MockReader(Reader):
  """Mock reader used for testing Keyczart."""
  
  def __init__(self, name, purpose, type, encrypted=False):
    self.kmd = keydata.KeyMetadata(name, purpose, type, encrypted)
    self.pubkmd = None
    self.keys = {}
    self.pubkeys = {}
  
  @property
  def numkeys(self):
    return len(self.keys)
  
  def GetMetadata(self):
    return str(self.kmd)
  
  def GetKey(self, version_number):
    try:
      return str(self.keys[version_number])
    except KeyError:
      raise errors.KeyczarError("Unrecognized Version Number")
  
  def GetStatus(self, version_number):
    return self.kmd.GetVersion(version_number).status
  
  def SetKey(self, version_number, key):
    self.keys[version_number] = key
  
  def SetPubKey(self, version_number, key):
    self.pubkeys[version_number] = key
  
  def AddKey(self, version_number, status, size=None):
    """Utility method for testing."""
    key = keys.GenKey(self.kmd.type, size)
    self.keys[version_number] = key
    return self.kmd.AddVersion(keydata.KeyVersion(version_number, status, 
                                                  False))
  
  def RemoveKey(self, version_number):
    """Mocks out deleting revoked key files."""
    self.keys.pop(version_number)
  
  def ExistsVersion(self, version_number):
    return version_number in self.keys
  
  def HasPubKey(self, version_number):
    priv = self.keys[version_number]
    pub = self.pubkeys[version_number]
    return priv.public_key == pub
  
  def GetKeySize(self, version_number):
    return self.keys[version_number].size
  