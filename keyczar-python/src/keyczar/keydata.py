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

class KeyMetadata(object):
  
  """Encodes metadata for a keyset with a name, purpose, type, and versions."""
    
  def __init__(self, name, purpose, type):
    self.name = name
    self.purpose = purpose
    self.type = type
    self.__versions = {}
    
  versions = property(lambda self: self.__versions.values())
    
  def __str__(self):
    return "%s - %s - %s" % (self.name, self.purpose, self.type)
  
  def AddVersion(self, version):
    num = version.version_number
    if num not in self.__versions:
      self.__versions[num] = version
      return True
    return False
  
  def RemoveVersion(self, version_num):
    return self.__versions.pop(version_num, False)  # return False if not found
  
  def GetVersion(self, version_number):
    return self.__versions.get(version_number)
  
  @staticmethod
  def Read(kmd):
    """Return KeyMetadata object constructed from JSON dictionary.
    
    Args:
      kmd: dictionary Read from JSON file
    
    Returns: 
      A KeyMetadata object
    """
    return KeyMetadata(kmd['name'], kmd['purpose'], kmd['type'])

class KeyVersion(object):
  def __init__(self, v, s, export):
    self.version_number = v
    self.__status = s
    self.exportable = export
    
  def __SetStatus(self, new_status):
    if new_status:
      self.__status = new_status
      
  status = property(lambda self: self.__status, __SetStatus)