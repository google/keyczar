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
Testcases to test behavior of Keyczar Signers.

@author: arkajit.dey@gmail.com (Arkajit Dey)
"""
from __future__ import absolute_import

import os
import unittest
import datetime

from keyczar import keyczar
from keyczar import util

class CollisionTest(unittest.TestCase):

  TEST_DATA = os.path.realpath(os.path.join(os.getcwd(), "test-data", "special-case"))

  def setUp(self):
    self.input = "This is some test data"

  def __testDecrypt(self, subdir):
    path = os.path.join(self.TEST_DATA, subdir)
    crypter = keyczar.Crypter.Read(path)
    active_ciphertext = util.ReadFile(os.path.join(path, "1.out"))
    primary_ciphertext = util.ReadFile(os.path.join(path, "2.out"))
    active_decrypted = crypter.Decrypt(active_ciphertext)
    self.assertEqual(self.input, active_decrypted)
    primary_decrypted = crypter.Decrypt(primary_ciphertext)
    self.assertEqual(self.input, primary_decrypted)

  def __readGoldenOutput(self, subdir, public=False):
    path = os.path.join(self.TEST_DATA, subdir)
    if not public:
      czar = keyczar.Verifier.Read(path)
    else:
      czar = keyczar.Verifier.Read(os.path.join(self.TEST_DATA, 
        subdir+".public"))
    active_sig = util.ReadFile(os.path.join(path, "1.out"))
    primary_sig = util.ReadFile(os.path.join(path, "2.out"))
    return (czar, active_sig, primary_sig)

  def __testVerify(self, subdir):
    (verifier, active_sig, primary_sig) = self.__readGoldenOutput(subdir)
    self.assertTrue(verifier.Verify(self.input, active_sig))
    self.assertTrue(verifier.Verify(self.input, primary_sig))
 
  def __testVerifyAttached(self, subdir, secret="", public =False):
    path = os.path.join(self.TEST_DATA, subdir)
    verifypath = path
    if public:
      verifypath = path +".public"
    ext = ".attached"
    if secret:
      ext = "." + secret + ext
    message = util.ReadFile(os.path.join(path, "2" + ext))
    verifier = keyczar.Verifier.Read(verifypath)
    self.assertTrue(verifier.AttachedVerify(message, secret))

  def __testVerifyTimeout(self, subdir, expired =False, public =False):
    path = os.path.join(self.TEST_DATA, subdir)
    verifypath = path
    if public:
      verifypath = path +".public"
    date = lambda: datetime.datetime(2012, 12, 21, 11, 6)
    if expired:
      date = lambda:datetime.datetime(2012, 12, 21, 11, 16)
    sig = util.ReadFile(os.path.join(path, "2.timeout"))
    verifier = keyczar.TimeoutVerifier.Read(verifypath)
    verifier.SetCurrentTimeFunc(date)
    self.assertEqual(verifier.Verify(self.input, sig), not expired)

  def testAesKeyDecrypt(self):
    self.__testDecrypt(os.path.join("key-collision", "aes"))

  def testRsaKeyDecrypt(self):
    self.__testDecrypt(os.path.join("key-collision", "rsa"))

  def testHmacKeyVerify(self):
    self.__testVerify(os.path.join("key-collision", "hmac"))

  def testHmacKeyVerifyTimeoutSuccess(self):
    self.__testVerifyTimeout(os.path.join("key-collision", "hmac"))

  def testHmacKeyVerifyTimeoutExpired(self):
    self.__testVerifyTimeout(os.path.join("key-collision", "hmac"), True)

  def testHmacKeyVerifyAttached(self):
    self.__testVerifyAttached(os.path.join("key-collision", "hmac"))

  def testHmacKeyVerifyAttachedSecret(self):
    self.__testVerifyAttached(os.path.join("key-collision", "hmac"), "secret")

  def testDsaKeyVerify(self):
    self.__testVerify(os.path.join("key-collision", "dsa"))

  def testDsaKeyVerifyTimeoutSuccess(self):
    self.__testVerifyTimeout(os.path.join("key-collision", "dsa"))

  def testDsaKeyVerifyTimeoutExpired(self):
    self.__testVerifyTimeout(os.path.join("key-collision", "dsa"), True)

  def testDsaKeyVerifyAttached(self):
    self.__testVerifyAttached(os.path.join("key-collision", "dsa"))

  def testDsaKeyVerifyAttachedSecret(self):
    self.__testVerifyAttached(os.path.join("key-collision", "dsa"), "secret")

  def testRsaKeyVerify(self):
    self.__testVerify(os.path.join("key-collision", "rsa-sign"))

  def testRsaKeyVerifyTimeoutSuccess(self):
    self.__testVerifyTimeout(os.path.join("key-collision", "rsa-sign"))

  def testRsaKeyVerifyTimeoutExpired(self):
    self.__testVerifyTimeout(os.path.join("key-collision", "rsa-sign"), True)

  def testRsaKeyVerifyAttached(self):
    self.__testVerifyAttached(os.path.join("key-collision", "rsa-sign"))

  def testRsaKeyVerifyAttachedSecret(self):
    self.__testVerifyAttached(os.path.join("key-collision", "rsa-sign"), 
      "secret")

  def tearDown(self):
    self.input = None

def suite():
  suite = unittest.TestSuite()
  suite.addTests(unittest.TestLoader().loadTestsFromTestCase(CollisionTest))
  return suite

if __name__ == "__main__":
  unittest.main(defaultTest='suite')
