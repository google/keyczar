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

"""Represents cryptographic keys in Keyczar.

Identifies a key by its hash and type. Includes several subclasses
of base class Key.

@author: steveweis@gmail.com (Steve Weis) 
@author: arkajit.dey@gmail.com (Arkajit Dey)
"""

import keytype

class Key:
  """Parent class for Keyczar Keys."""

  def __init__(self, type, hash):
    self.type = type
    self.hash = hash
    self.size = type.default_size() # initially default
    
  def __str__(self):
    return "(%s %s)" % (self.type, self.hash)  

  def type(self):
    return self.type
  
  def size(self):
    return self.size
  
  def hash(self):
    return self.hash
  
  def read(data):
    """Return Key object constructed from JSON dictionary.
    
    Args:
      data: dictionary read from JSON file
    
    Returns:
      A Key object
    """
    return Key(data['type'], data['hash'])
  read = staticmethod(read)

class PrivateKey(Key):
  """Represents private keys in Keyczar."""
  
  def __init__(self, type, hash, pkcs8):
    Key.__init__(type, hash)
    self.pkcs8 = pkcs8
    
  def getPublic(self):
    pass
  
  def setPublic(self):
    pass

class PublicKey(Key):
  """Represents public keys in Keyczar."""
  
  def __init__(self, type, hash, x509):
    Key.__init__(type, hash)
    self.x509 = x509