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

"""
A Reader supports reading metadata and key info for key sets.

@author: arkajit.dey@gmail.com (Arkajit Dey)
"""
                
import os

class Reader(object):
  """Interface providing supported methods (no implementation)."""

  def GetMetadata(self):
    """
    Return the KeyMetadata for the key set being read.
    
    @return: JSON string representation of KeyMetadata object
    @rtype: string
    """
  
  def GetKey(self, version_number):
    """
    Return the key corresponding to the given version.
    
    @param version_number: the version number of the desired key
    @type version_number: integer
    
    @return: JSON string representation of a Key object
    @rtype: string
    """

class FileReader(Reader):
  
  """Reader that reads key data from files."""
  
  def __init__(self, location):
    self.__location = location
    
  def GetMetadata(self):
    return open(os.path.join(self.__location, "meta")).read()

  def GetKey(self, version_number):
    return open(os.path.join(self.__location, str(version_number))).read()