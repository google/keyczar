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

class KeyMetadata(object):
  """Encodes metadata for a keyset with a name, purpose, type, and versions."""
    
  def __init__(self, name, purpose, type, versions):
    self.name = name
    self.purpose = purpose
    self.type = type
    self.versions = versions
    
  def __str__(self):
    return "%s - %s - %s" % (self.name, self.purpose, self.type)
  
  @staticmethod
  def Read(kmd):
    """Return KeyMetadata object constructed from JSON dictionary.
    
    Args:
      kmd: dictionary Read from JSON file
    
    Returns: 
      A KeyMetadata object
    """
    return KeyMetadata(kmd['name'], kmd['purpose'], 
                       kmd['type'], kmd['versions'])

class KeyVersion(object):
  def __init__(self, v, s, export):
    self.version = v
    self.status = s
    self.exportable = export
    
  status = property(lambda self: self.status, __SetStatus)
    
  def __SetStatus(self, new_status):
    if new_status:
      self.status = new_status