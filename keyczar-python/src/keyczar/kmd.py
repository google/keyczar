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

class KeyMetadata:
  def __init__(self, name, purpose, type, versions):
    self.name = name
    self.purpose = purpose
    self.type = type
    self.versions = versions
    
  def __str__(self):
    return "%s - %s - %s" % (self.name, self.purpose, self.type)
  
  def name(self):
    return self.name
  
  def purpose(self):
    return self.purpose
  
  def type(self):
    return self.type
  
  def versions(self):
    return self.versions
  
  def read(kmd):
    """Return KeyMetadata object constructed from JSON dictionary.
    
    Args:
      kmd: dictionary read from JSON file
    
    Returns: 
      A KeyMetadata object
    """
    return KeyMetadata(kmd['name'], kmd['purpose'], 
                       kmd['type'], kmd['versions'])
  read = staticmethod(read)