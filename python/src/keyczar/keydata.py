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
Encodes the two classes storing data about keys:
  - KeyMetadata: stores metadata
  - KeyVersion: stores key strings and types

@author: arkajit.dey@gmail.com (Arkajit Dey)
"""
try:
  import simplejson as json
except ImportError:
  import json

import errors
import keyinfo

class KeyMetadata(object):
  """Encodes metadata for a keyset with a name, purpose, type, and versions."""

  def __init__(self, name, purpose, key_type, encrypted=False):
    self.name = name
    self.purpose = purpose
    self.type = key_type
    self.encrypted = encrypted
    self.__versions = {}  # dictionary from version nums to KeyVersions

  versions = property(lambda self: self.__versions.values())

  def __str__(self):
    return json.dumps({"name": self.name,
                       "purpose": str(self.purpose),                              
                       "type": str(self.type),
                       "encrypted": self.encrypted,
                       "versions": [json.loads(str(v)) for v in self.versions]})

  def AddVersion(self, version):
    """
    Adds given version and returns True if successful.

    @param version: version to add
    @type version: L{KeyVersion}

    @return: True if version was successfully added (i.e. no previous version
      had the same version number), False otherwise.
    @rtype: boolean
    """
    num = version.version_number
    if num not in self.__versions:
      self.__versions[num] = version
      return True
    return False

  def RemoveVersion(self, version_number):
    """
    Removes version with given version number and returns it if it exists.

    @param version_number: version number to remove
    @type version_number: integer

    @return: the removed version if it exists
    @rtype: L{KeyVersion}

    @raise KeyczarError: if the version number is non-existent
    """
    try:
      self.__versions.pop(version_number)
    except KeyError:
      raise errors.KeyczarError("No such version number: %d" % version_number)

  def GetVersion(self, version_number):
    """
    Return the version corresponding to the given version number.

    @param version_number: integer version number of desired version
    @type version_number: integer

    @return: the corresponding version if it exists
    @rtype: L{KeyVersion}

    @raise KeyczarError: if the version number is non-existent.
    """
    try:
      return self.__versions[version_number]
    except KeyError:
      raise errors.KeyczarError("No such version number: %d" % version_number)

  @staticmethod
  def Read(json_string):
    """
    Return KeyMetadata object constructed from JSON string representation.

    @param json_string: a JSON representation of a KeyMetadata object
    @type json_string: string

    @return: the constructed KeyMetadata object
    @rtype: L{KeyMetadata}
    """
    meta = json.loads(json_string)
    kmd = KeyMetadata(meta['name'], keyinfo.GetPurpose(meta['purpose']),
                      keyinfo.GetType(meta['type']), meta['encrypted'])
    for version in meta['versions']:
      kmd.AddVersion(KeyVersion.Read(version))
    return kmd

class KeyVersion(object):
  def __init__(self, v, s, export):
    self.version_number = v
    self.__status = s
    self.exportable = export

  def __SetStatus(self, new_status):
    if new_status:
      self.__status = new_status

  status = property(lambda self: self.__status, __SetStatus)

  def __str__(self):
    return json.dumps({"versionNumber": self.version_number,
                             "status": str(self.status),
                             "exportable": self.exportable})

  @staticmethod
  def Read(version):
    """
    Return KeyVersion object constructed from dictionary derived from JSON.

    @param version: a dictionary obtained from a JSON string representation
    @type version: dictionary

    @return: constructed KeyVersion object
    @rtype: L{KeyVersion}
    """
    return KeyVersion(version['versionNumber'],
                      keyinfo.GetStatus(version['status']),
                      version['exportable'])
