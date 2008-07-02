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

"""A Reader supports reading GetMetadata and GetKey info for key sets."""

__author__ = """steveweis@gmail.com (Steve Weis), 
                arkajit.dey@gmail.com (Arkajit Dey)"""

import keydata
import keys
import simplejson

class Reader(object):
  """ Interface providing supported methods (no implementation). """

  def GetMetadata(self):
    """Return the KeyMetadata for the GetKey set being Read. Abstract method.
    
    @return KeyMetadata object
    """
  
  def GetKey(self, version):
    """Return the GetKey corresponding to the given version. Abstract method.
    
    @param version, the integer version number
    @return GetKey object
    """

class FileReader(Reader):
  def __init__(self, location):
    self.__loc = location
    
  def GetMetadata(self):
    metadata = simplejson.loads(open(self.__loc + "/meta").read())
    return keydata.KeyMetadata.Read(metadata)

  def GetKey(self, version_num):
    keyData = simplejson.loads(open(self.__loc + "/" + str(version_num)).read())
    return keys.Key.Read(keyData)