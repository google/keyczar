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

""" An 'enum' defining different key types and their properties.

Defines the following Key Types:
  AES
  HMAC-SHA1
  DSA Private
  DSA Public
  RSA Private
  RSA Public

@author: steveweis@gmail.com (Steve Weis) 
@author: arkajit.dey@gmail.com (Arkajit Dey)
"""

class KeyType: 
  def __init__(self, name, id, sizes, output_size):
    self.name = name
    self.id = id
    self.sizes = sizes
    self.size = sizes[0]  # default size
    self.output_size = output_size

  def __str__(self):
    return self.name
  
  def output_size(self):
    return self.output_size
  
  def default_size(self):
    return self.sizes[0]
  
  def size(self):
    return self.size
  
  def setSize(self, newSize):
    if newSize in self.sizes:
      self.size = newSize
      
  def resetSize(self):
    self.size = self.default_size()

AES = KeyType("AES", 0, [128, 192, 256], 0)
HMAC_SHA1 = KeyType("HMAC-SHA1", 1, [256], 20)
DSA_PRIV = KeyType("DSA Private", 2, [1024], 48)
DSA_PUB = KeyType("DSA Public", 3, [1024], 48)
RSA_PRIV = KeyType("RSA Private", 4, [2048, 1024, 768, 512], 256)
RSA_PUB = KeyType("RSA Public", 4, [2048, 1024, 768, 512], 256)
types = {AES.id : AES, HMAC_SHA1.id : HMAC_SHA1, DSA_PRIV.id : DSA_PRIV, 
         DSA_PUB.id : DSA_PUB, RSA_PRIV.id : RSA_PRIV, RSA_PUB.id : RSA_PUB}

def getType(value):
    if value in types:
      return types[value]