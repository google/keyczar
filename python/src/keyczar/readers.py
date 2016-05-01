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
import keyinfo
import keys
import util

def CreateReader(location):
  """Factory function for Reader's
  
    @param location: where (file, uri, etc) the reader should read from
    @type location: string
  """
  # make sure all readers are available
  util.ImportBackends()
  # return the first that accepts the location
  for sc in Reader.__subclasses__():
    reader = sc.CreateReader(location)
    if reader:
      return reader
  raise errors.KeyczarError(
    "Unable to create a reader for %s. Does the location exist?" % location)

class Reader(object):
  """Interface providing supported methods (no implementation)."""

  __metaclass__ = util.ABCMeta

  @util.abstractmethod
  def GetMetadata(self):
    """
    Return the KeyMetadata for the key set being read.
    
    @return: JSON string representation of KeyMetadata object
    @rtype: string
    
    @raise KeyczarError: if unable to read metadata (e.g. IOError) 
    """
    return
  
  @util.abstractmethod
  def GetKey(self, version_number):
    """
    Return the key corresponding to the given version.
    
    @param version_number: the version number of the desired key
    @type version_number: integer
    
    @return: JSON string representation of a Key object
    @rtype: string
    
    @raise KeyczarError: if unable to read key info (e.g. IOError) 
    """
    return

  @util.abstractmethod
  def Close(self):
    """
    Clean up this reader
    
    @raise KeyczarError: if error during close
    """
    return

  @classmethod
  def CreateReader(cls, location):
    """
    Return an instance of this class if it handles the location

    @param location: where (file, uri, etc) the reader should read from
    @type location: string
    """
    raise NotImplementedError('CreateReader() class method MUST be implemented for:%s' %cls)

class FileReader(Reader):
  """Reader that reads key data from files."""
  
  def __init__(self, location):
    self._location = location
    
  def GetMetadata(self):
    return util.ReadFile(os.path.join(self._location, "meta"))

  def GetKey(self, version_number):
    return util.ReadFile(os.path.join(self._location, str(version_number)))
  
  def Close(self):
    # Nothing to close - util.ReadFile() closes it
    return
  
  @classmethod
  def CreateReader(cls, location):
    result = None
    location = str(location) # This fixes the case in case the location is
                             # an instance of Path (from django-environ)
    if os.path.exists(location):
      result = FileReader(location)
    return result

class StaticKeyReader(Reader):
  """Reader that returns a static key"""

  def __init__(self, key, purpose):
    self._key = key
    self._meta = keydata.KeyMetadata("Imported", purpose, key.type)
    self._meta.AddVersion(keydata.KeyVersion(1, keyinfo.PRIMARY, False))

  def GetMetadata(self):
    return str(self._meta)

  def GetKey(self, version_number):
    return str(self._key)

  def Close(self):
    # Nothing to close - util.ReadFile() closes it
    return

  @classmethod
  def CreateReader(cls, location):
    # cannot be instantiated indirectly
    return

class EncryptedReader(Reader):
  """Reader that reads encrypted key data from files."""
  
  def __init__(self, reader, crypter):
    self._reader = reader
    self._crypter = crypter
  
  def GetMetadata(self):
    return self._reader.GetMetadata()
  
  def GetKey(self, version_number):
    return self._crypter.Decrypt(self._reader.GetKey(version_number))

  def Close(self):
    # Nothing to close - util.ReadFile() closes it
    return

  @classmethod
  def CreateReader(cls, location):
    # cannot be instantiated
    return

class MockReader(Reader):
  """Mock reader used for testing Keyczart."""
  
  def __init__(self, name, purpose, key_type, encrypted=False):
    self.kmd = keydata.KeyMetadata(name, purpose, key_type, encrypted)
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
  
  def Close(self):
    # Nothing to close
    return

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
  
  @classmethod
  def CreateReader(cls, location):
    # cannot be instantiated
    return
