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
Contains hierarchy of all possible exceptions thrown by Keyczar.

@author: arkajit.dey@gmail.com (Arkajit Dey)
"""

class KeyczarError(Exception):
  """Indicates exceptions raised by a Keyczar class."""

class BadVersionError(KeyczarError):
  """Indicates a bad version number was received."""
  
  def __init__(self, version):
    KeyczarError.__init__(self, 
                          "Received a bad version number: " + str(version)) 

class Base64DecodingError(KeyczarError):
  """Indicates an error while performing Base 64 decoding."""

class InvalidSignatureError(KeyczarError):
  """Indicates an invalid ciphertext signature."""
  
  def __init__(self):
    KeyczarError.__init__(self, "Invalid ciphertext signature")

class KeyNotFoundError(KeyczarError):
  """Indicates a key with a certain hash id was not found."""
  
  def __init__(self, hash_val):
    KeyczarError.__init__(self, 
                          "Key with hash_val identifier %s not found." % hash_val)

class ShortCiphertextError(KeyczarError):
  """Indicates a ciphertext too short to be valid."""
  
  def __init__(self, length):
    KeyczarError.__init__(self, 
            "Input of length %s is too short to be valid ciphertext." % length)

class ShortSignatureError(KeyczarError):  
  """Indicates a signature too short to be valid."""
  
  def __init__(self, length):
    KeyczarError.__init__(self, 
              "Input of length %s is too short to be valid signature." % length)

class NoPrimaryKeyError(KeyNotFoundError):  
  """Indicates missing primary key."""
  
  def __init__(self):
    KeyczarError.__init__(self, "No primary key found")
