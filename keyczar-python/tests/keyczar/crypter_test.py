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

__author__ = """arkajit.dey@gmail.com (Arkajit Dey)"""

from keyczar import keyczar
#FIXME: want to import keyczar module in keyczar package

import unittest
import os

TEST_DATA = os.path.realpath(os.path.join(os.getcwd(), "..", "..", "testdata"))

class CrypterTest(unittest.TestCase):
  
  def setUp(self):
    self.input = "May the Force be with you always"
  
  def testAesDecrypt(self):
    pass
  
  def testRsaDecrypt(self):
    pass
  
  def testAesEncryptAndDecrypt(self):
    crypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, "aes"))
    ciphertext = crypter.Encrypt(self.input)
    plaintext = crypter.Decrypt(ciphertext)
    self.assertEquals(self.input, plaintext)
  
  def testRsaEncryptAndDecrypt(self):
    pass
  
  def testBadAesCiphertexts(self):
    pass
  
  def tearDown(self):
    pass