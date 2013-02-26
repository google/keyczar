#!/usr/bin/python
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
Testcases to test behavior of Keyczart.

@author: arkajit.dey@gmail.com (Arkajit Dey)
"""
from __future__ import absolute_import

import unittest

from keyczar import readers
from keyczar import writers
from keyczar.tool import keyczart
from keyczar import keyczar
from keyczar import keyinfo

class KeyczartTest(unittest.TestCase):

  def setUp(self):
    self.mock = readers.MockReader('TEST', keyinfo.ENCRYPT, keyinfo.AES)
    self.mock.AddKey(42, keyinfo.PRIMARY)
    self.mock.AddKey(77, keyinfo.ACTIVE)
    self.mock.AddKey(99, keyinfo.INACTIVE)
    keyczart.mock = self.mock  # enable testing

  def testCreate(self):
    keyczart.main(['create', '--name=testCreate',
                   '--purpose=crypt', '--asymmetric=rsa'])
    self.assertEqual('testCreate', self.mock.kmd.name)
    self.assertEqual(keyinfo.DECRYPT_AND_ENCRYPT, self.mock.kmd.purpose)
    self.assertEqual(keyinfo.RSA_PRIV, self.mock.kmd.type)

  def testAddKey(self):
    self.assertEqual(3, self.mock.numkeys)
    keyczart.main(['addkey', '--status=primary'])
    self.assertEqual(4, self.mock.numkeys)
    # The next version number will be 100, since the previous max was 99
    self.assertEqual(keyinfo.PRIMARY, self.mock.GetStatus(100))
    self.assertEqual(keyinfo.ACTIVE, self.mock.GetStatus(42))

  def testAddKeySizeFlag(self):
    keyczart.main(['addkey', '--size=256'])
    self.assertEqual(256, self.mock.GetKeySize(100))

  def testAddKeyCrypterCreatesCrypter(self):
    self.dummy_location = None
    def dummyCreateCrypter(location):
      self.dummy_location = location
      return self.mock
    keyczart._CreateCrypter = dummyCreateCrypter
    keyczart.main(['addkey', '--crypter=foo'])
    self.assertEqual(self.dummy_location, 'foo')

  def testPubKey(self):
    pubmock = readers.MockReader('PUBTEST', keyinfo.DECRYPT_AND_ENCRYPT,
                                 keyinfo.RSA_PRIV)
    pubmock.AddKey(33, keyinfo.PRIMARY, 1024)  # small key size for fast tests
    keyczart.mock = pubmock  # use pubmock instead
    self.assertEqual(None, pubmock.pubkmd)
    keyczart.main(['pubkey'])
    self.assertNotEqual(None, pubmock.pubkmd)
    self.assertEqual('PUBTEST', pubmock.pubkmd.name)
    self.assertEqual(keyinfo.ENCRYPT, pubmock.pubkmd.purpose)
    self.assertEqual(keyinfo.RSA_PUB, pubmock.pubkmd.type)
    self.assertTrue(pubmock.HasPubKey(33))

  def testPromote(self):
    keyczart.main(['promote', '--version=77'])
    self.assertEqual(keyinfo.PRIMARY, self.mock.GetStatus(77))
    self.assertEqual(keyinfo.ACTIVE, self.mock.GetStatus(42))

  def testDemote(self):
    keyczart.main(['demote', '--version=77'])
    self.assertEqual(keyinfo.INACTIVE, self.mock.GetStatus(77))

  def testRevoke(self):
    self.assertTrue(self.mock.ExistsVersion(99))
    keyczart.main(['revoke', '--version=99'])
    self.assertFalse(self.mock.ExistsVersion(99))

  def testWriteIsBackwardCompatible(self):
    class MockWriter(writers.Writer):

      num_created = 0

      def WriteMetadata(self, metadata, overwrite=True):
        return
      
      def WriteKey(self, key, version_number, encrypter=None):
        return

      def Remove(self, version_number):
        return

      def Close(self):
        return

      @classmethod
      def CreateWriter(cls, location):
        MockWriter.num_created += 1
        return MockWriter()

    generic_keyczar = keyczar.GenericKeyczar(self.mock)
    generic_keyczar.Write('foo')
    self.assertEqual(1, MockWriter.num_created, 
                      'Write("string") should have created a new writer')

  def tearDown(self):
    keyczart.mock = None

def suite():
  suite = unittest.TestSuite()
  suite.addTests(unittest.TestLoader().loadTestsFromTestCase(KeyczartTest))
  return suite

if __name__ == "__main__":
  unittest.main(defaultTest='suite')
