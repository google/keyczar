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
                
import keyinfo
import errors
import simplejson

class KeyMetadata(object):
  
  """Encodes metadata for a keyset with a name, purpose, type, and versions."""
    
  def __init__(self, name, purpose, type):
    self.name = name
    self.purpose = purpose
    self.type = type
    self.__versions = {}  # dictionary from version nums to KeyVersions
    
  versions = property(lambda self: self.__versions.values())
    
  def __str__(self):
    return "%s - %s - %s" % (self.name, self.purpose, self.type)
  
  def AddVersion(self, version):
    num = version.version_number
    if num not in self.__versions:
      self.__versions[num] = version
      return True
    return False
  
  def RemoveVersion(self, version_number):
    """Removes version with given version number and returns it if it exists.
    
    Args:
      version_number: integer version number to remove
    
    Returns:
      KeyVersion: the removed version if it exists or None.
    """
    return self.__versions.pop(version_number, None)
  
  def GetVersion(self, version_number):
    """Returns the version corresponding to the given version number.
    
    Args:
      version_number: integer version number of desired KeyVersion
    
    Returns:
      KeyVersion: the corresponding version if it exists
    
    Raises:
      KeyczarError: If the version number is non-existent.
    """
    version = self.__versions.get(version_number)
    if version is None:
      raise errors.KeyczarError("No such version number: %d" % version_number)
    else:
      return version
  
  @staticmethod
  def Read(json_string):
    """Return KeyMetadata object constructed from JSON string representation.
    
    Args:
      json_string: a JSON representation of a KeyMetadata object
    
    Returns: 
      A KeyMetadata object
    """
    meta = simplejson.loads(json_string)
    kmd = KeyMetadata(meta['name'], keyinfo.GetPurpose(meta['purpose']), 
                      keyinfo.GetType(meta['type']))
    for version in meta['versions']:
      kmd.AddVersion(KeyVersion.Read(version))
    return kmd

class KeyVersion(object):
  def __init__(self, v, s, export):
    self.version_number = v
    self.__status = s
    self.exportable = export
    
  def __SetStatus(self, new_status):
    if new_status:
      self.__status = new_status
      
  status = property(lambda self: self.__status, __SetStatus)
  
  def __str__(self):
    return "(%d, %s, %s)" % (self.version_number, self.status, self.exportable)
  
  @staticmethod
  def Read(version):
    """Return KeyVersion object constructed from dictionary derived from JSON.
    
    Args:
      version: a dictionary obtained from a JSON string representation.
    
    Returns: 
      A KeyVersion object
    """
    return KeyVersion(int(version['versionNumber']),
                      keyinfo.GetStatus(version['status']),
                      version['exportable'])
    