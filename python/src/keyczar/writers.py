#
# Copyright 2011 LightKeeper LLC.
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
A Writer supports writing metadata and key info for key sets.

@author: rleftwich@lightkeeper.com (Robert Leftwich)
"""
import os

import errors
import util

def CreateWriter(location):
  """Factory function for Writers
  
    @param location: where (file, uri, etc) the writer should write to
    @type location: string
  """
  # make sure all writers are available
  util.ImportBackends()
  for sc in Writer.__subclasses__():
    writer = sc.CreateWriter(location)
    if writer:
      return writer
  raise errors.KeyczarError(
    "Unable to create a writer for %s. Does the location exist?" % location)

class Writer(object):
  """Abstract class/interface providing supported methods for writing key sets."""

  __metaclass__ = util.ABCMeta

  @util.abstractmethod
  def WriteMetadata(self, metadata, overwrite=True):
    """
    Write the metadata for the key.
    
    @param metadata: metadata for key
    @type: KeyMetadata
    
    @raise KeyczarError: if unable to write metadata (e.g. IOError) 
    """
    return
  
  @util.abstractmethod
  def WriteKey(self, key, version_number, encrypter=None):
    """
    Write out the key at the given version.
    
    @param key: key value
    @type: string
    
    @param version_number: the version number of the key
    @type version_number: integer
    
    @param encrypter: existing Keyczar encrypter for key
    @type: Keyczar.Crypter

    @raise KeyczarError: if unable to write key info (e.g. IOError) 
    """
    return

  @util.abstractmethod
  def Remove(self, version_number):
    """
    Remove the key for the given version.
    
    @param version_number: the version number of the key
    @type version_number: integer
    
    @raise KeyczarError: if unable to remove key info (e.g. IOError) 
    """
    return

  @util.abstractmethod
  def Close(self):
    """
    Clean up this writer
    
    @raise KeyczarError: if error during close
    """
    return

  @classmethod
  def CreateWriter(cls, location):
    """
    Return an instance of this class if it handles the location
    """
    raise NotImplementedError('CreateWriter() class method MUST be implemented for:%s' %cls)

class FileWriter(Writer):
  """Write key sets to a file."""

  def __init__(self, location):
    """Construct a key set writer at the specified location"""
    self.location = location

  def WriteMetadata(self, metadata, overwrite=True):
    """
    Write the metadata for the key.
    """
    fname = os.path.join(self.location, "meta")
    if not overwrite and os.path.exists(fname):
        raise errors.KeyczarError("File:%s already exists" %fname)
    util.WriteFile(str(metadata), fname)
    return
  
  def WriteKey(self, key, version_number, encrypter=None):
    """
    Write out the key at the given version.
    """
    key = str(key)
    if encrypter:
      key = encrypter.Encrypt(key)  # encrypt key info before outputting
    util.WriteFile(key, os.path.join(self.location, str(version_number)))
    return

  def Remove(self, version_number):
    """
    Remove the key for the given version.
    """
    os.remove(os.path.join(self.location, str(version_number)))

  def Close(self):
    """
    Clean up this writer
    """
    # no-op
    return

  @classmethod
  def CreateWriter(cls, location):
    """
    Return an instance of this class if it handles the location
    """
    result = None
    if os.path.exists(location):
      result = FileWriter(location)
    return result
