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
Testcases to test behavior of Keyczar Crypters.

@author: arkajit.dey@gmail.com (Arkajit Dey)
"""

from keyczar import keyczar
from keyczar import errors
from keyczar import util

import unittest
import os

TEST_DATA = os.path.realpath(os.path.join(os.getcwd(), "..", "..", "testdata"))

class CrypterTest(unittest.TestCase):
  
  def setUp(self):
    self.input = "Hello Google"
  
  def __testDecrypt(self, subdir):
    path = os.path.join(TEST_DATA, subdir)
    crypter = keyczar.Crypter.Read(path)
    active_ciphertext = open(os.path.join(path, "1out")).read()
    primary_ciphertext = open(os.path.join(path, "2out")).read()
    active_decrypted = crypter.Decrypt(active_ciphertext)
    self.assertEquals(self.input, active_decrypted)
    primary_decrypted = crypter.Decrypt(primary_ciphertext)
    self.assertEquals(self.input, primary_decrypted)
  
  def __testEncryptAndDecrypt(self, subdir):
    crypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, subdir))
    ciphertext = crypter.Encrypt(self.input)
    plaintext = crypter.Decrypt(ciphertext)
    self.assertEquals(self.input, plaintext)
  
  def testAesDecrypt(self):
    self.__testDecrypt("aes")
    
  def testRsaDecrypt(self):
    self.__testDecrypt("rsa")
  
  def testAesEncryptAndDecrypt(self):
    self.__testEncryptAndDecrypt("aes")
  
  def testRsaEncryptAndDecrypt(self):
    self.__testEncryptAndDecrypt("rsa")
  
  def testBadAesCiphertexts(self):
    crypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, "aes"))
    ciphertext = util.Decode(crypter.Encrypt(self.input))  # in bytes
    bad = util.Encode(chr(0))
    char = chr(ord(ciphertext[2]) ^ 44)  # Munge key hash info in ciphertext
    ciphertext = util.Encode(ciphertext[:2]+char+ciphertext[3:])
    self.assertRaises(errors.ShortCiphertextError, crypter.Decrypt, bad)
    self.assertRaises(errors.KeyNotFoundError, crypter.Decrypt, ciphertext)
  
  def tearDown(self):
    self.input = None