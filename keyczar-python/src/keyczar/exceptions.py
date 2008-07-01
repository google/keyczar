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

"""Contains hierarchy of all possible exceptions thrown by Keyczar."""

__author__ = """arkajit.dey@gmail.com (Arkajit Dey)"""

class KeyczarException(Exception):
  """Indicates exceptions raised by a Keyczar class."""

class BadVersionException(KeyczarException):
  
  """Indicates a bad version number was received."""
  
  def __init__(self, version):
    KeyczarException.__init__(self, 
                              "Received a bad version number: " + str(version))

class Base64DecodingException(KeyczarException):
  """Indicates an error while performing Base 64 decoding."""

class InvalidSignatureException(KeyczarException):
  
  """Indicates an invalid ciphertext signature."""
  
  def __init__(self):
    KeyczarException.__init__(self, "Invalid ciphertext signature")

class KeyNotFoundException(KeyczarException):
  
  """Indicates a key with a certain hash id was not found."""
  
  def __init__(self, hash):
    KeyczarException.__init__(self, 
                              "Key with hash identifier %s not found." % hash)

class ShortBufferException(KeyczarException):
  
  """Indicates a buffer with insufficient capacity."""
  
  def __init__(self, given, needed):
    KeyczarException.__init__(self, "Short Buffer. Given %s bytes. Need: %s" 
                                    % (given, needed))

class ShortCiphertextException(KeyczarException):
  
  """Indicates a ciphertext too short to be valid."""
  
  def __init__(self, length):
    KeyczarException.__init__(self, 
            "Input of length %s is too short to be valid ciphertext." % length)

class ShortSignatureException(KeyczarException):
  
  """Indicates a signature too short to be valid."""
  
  def __init__(self, length):
    KeyczarException.__init__(self, 
              "Input of length %s is too short to be valid signature." % length)


class NoPrimaryKeyException(KeyNotFoundException):
  
  """Indicates missing primary key."""
  
  def __init__(self):
    KeyczarException.__init__(self, "No primary key found")