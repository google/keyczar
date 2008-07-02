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

import readers
import keydata
import keyinfo
import exceptions

class Keyczar(object):
  
  """Abstract Keyczar class"""
    
  def __init__(self, reader):
    self.metadata = reader.GetMetadata()
    self.keys = {}
    self.primary_version = None
    if not self.IsAcceptablePurpose(self.metadata.purpose):
      raise KeyczarException("Unacceptable purpose: " + self.metadata.purpose)
    for version in self.metadata.versions:
      if version.status == keyinfo.PRIMARY:
        if self.primary_version is not None:
          raise KeyczarException(
              "Key sets may only have a single primary version")
        self.primary_version = version
      key = reader.GetKey(version.version_number)
      self.keys[version] = self.keys[key.hash] = key
  
  def __str__(self):
    return str(self.metadata)
  
  @staticmethod
  def Read(location):
    """ Return a Keyczar object created from FileReader at given location. """
    return Keyczar(readers.FileReader(location))
  
  def IsAcceptablePurpose(self, purpose):
    """Indicates whether purpose is valid. Abstract method."""

class GenericKeyczar(Keyczar):
  pass

class Encrypter(Keyczar):
  pass

class Verifier(Keyczar):
  pass

class Crypter(Encrypter):
  pass

class Signer(Verifier):
  pass


