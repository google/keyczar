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
from keyczar import errors
from keyczar import util

import unittest
import os

TEST_DATA = os.path.realpath(os.path.join(os.getcwd(), "..", "..", "testdata"))
AES = os.path.join(TEST_DATA, "aes")
RSA = os.path.join(TEST_DATA, "rsa")

class CrypterTest(unittest.TestCase):
  
  def setUp(self):
    self.input = "Hello Google"
  
  def __testDecrypt(self, subdir):
    crypter = keyczar.Crypter.Read(subdir)
    active_ciphertext = open(os.path.join(subdir, "1out")).read()
    primary_ciphertext = open(os.path.join(subdir, "2out")).read()
    active_decrypted = crypter.Decrypt(active_ciphertext)
    self.assertEquals(self.input, active_decrypted)
    primary_decrypted = crypter.Decrypt(primary_ciphertext)
    self.assertEquals(self.input, primary_decrypted)
  
  def __testEncryptAndDecrypt(self, subdir):
    crypter = keyczar.Crypter.Read(subdir)
    ciphertext = crypter.Encrypt(self.input)
    plaintext = crypter.Decrypt(ciphertext)
    self.assertEquals(self.input, plaintext)
  
  def testAesDecrypt(self):
    self.__testDecrypt(AES)
    
  def testRsaDecrypt(self):
    self.__testDecrypt(RSA)
  
  def testAesEncryptAndDecrypt(self):
    self.__testEncryptAndDecrypt(AES)
  
  def testRsaEncryptAndDecrypt(self):
    self.__testEncryptAndDecrypt(RSA)
  
  def testBadAesCiphertexts(self):
    crypter = keyczar.Crypter.Read(AES)
    ciphertext = util.Decode(crypter.Encrypt(self.input))  # in bytes
    bad = util.Encode(chr(0))
    char = chr(ord(ciphertext[2]) ^ 44)  # Munge key hash info in ciphertext
    ciphertext = util.Encode(ciphertext.replace(ciphertext[2], char, 1))
    self.assertRaises(errors.ShortCiphertextError, crypter.Decrypt, bad)
    self.assertRaises(errors.KeyNotFoundError, crypter.Decrypt, ciphertext)
  
  def tearDown(self):
    self.input = None