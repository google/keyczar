#!/usr/bin/python2.4
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
Testcases to test behavior of Keyczar Crypters.

@author: arkajit.dey@gmail.com (Arkajit Dey)
"""

import os
import unittest

from keyczar import errors
from keyczar import keyczar
from keyczar import readers
from keyczar import util
from keyczar import keys
from keyczar import keyinfo

TEST_DATA = os.path.realpath(os.path.join(os.getcwd(), "..", "testdata"))

class BaseCrypterTest(unittest.TestCase):
  
  def setUp(self):
    self.input = "This is some test data"
  
  def __testDecrypt(self, subdir, reader=None):
    path = os.path.join(TEST_DATA, subdir)
    if reader:
      crypter = keyczar.Crypter(reader)
    else:
      crypter = keyczar.Crypter.Read(path)
    active_ciphertext = util.ReadFile(os.path.join(path, "1.out"))
    primary_ciphertext = util.ReadFile(os.path.join(path, "2.out"))
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
  
  def testAesEncryptedKeyDecrypt(self):
    file_reader = readers.FileReader(os.path.join(TEST_DATA, "aes-crypted"))
    key_decrypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, "aes"))
    reader = readers.EncryptedReader(file_reader, key_decrypter)
    self.__testDecrypt("aes-crypted", reader)
    
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
  
class PyCryptoCrypterTest(BaseCrypterTest):
    
  def setUp(self):
    keys.ACTIVE_CRYPT_LIB = 'pycrypto'
    super(PyCryptoCrypterTest, self).setUp()

class M2CryptoCrypterTest(BaseCrypterTest):
    
  def setUp(self):
    keys.ACTIVE_CRYPT_LIB = 'm2crypto'
    super(M2CryptoCrypterTest, self).setUp()

class PyCryptoM2CryptoInteropTest(unittest.TestCase):
    
  def setUp(self):
    self.input = "The quick brown fox was not quick enough and is now an UNFOX!"

  def testKeysizeInterop(self):
    s = self.input
    # test for all valid sizes
    for size in keyinfo.AES.sizes:
      # generate a new key of this size
      aeskey = keys.AesKey.Generate(size)

      # ensure PyCrypto chosen
      keys.ACTIVE_CRYPT_LIB = 'pycrypto'
      self.assertEquals(
        aeskey.Decrypt(aeskey.Encrypt(s)), s, 
        'Cannot encrypt/decrypt with the same PyCrypto key! size:%s' %size
      )
      pycrypto_encrypted_str = aeskey.Encrypt(s)

      # now switch to M2Crypto
      keys.ACTIVE_CRYPT_LIB = 'm2crypto'
      self.assertEquals(
        aeskey.Decrypt(aeskey.Encrypt(s)), s,
        'Cannot encrypt/decrypt with the same M2Crypto key! size:%s' %size
      )
      m2crypto_encrypted_str = aeskey.Encrypt(s)

      self.assertEquals(
        aeskey.Decrypt(pycrypto_encrypted_str), s, 
        'Cannot decrypt PyCrypto with M2Crypto key! size:%s' %size
      )
      self.assertEquals(
        aeskey.Decrypt(m2crypto_encrypted_str), s,
        'Cannot decrypt M2Crypto with M2Crypto key! size:%s' %size
      )

      # now switch to PyCrypto
      keys.ACTIVE_CRYPT_LIB = 'pycrypto'
      self.assertEquals(
        aeskey.Decrypt(pycrypto_encrypted_str), s, 
        'Cannot decrypt PyCrypto with PyCrypto key! size:%s' %size
      )
      self.assertEquals(
        aeskey.Decrypt(m2crypto_encrypted_str), s,
        'Cannot decrypt M2Crypto with PyCrypto key! size:%s' %size
      )

def suite():
  alltests = unittest.TestSuite(
    [unittest.TestLoader().loadTestsFromTestCase(PyCryptoCrypterTest),
     unittest.TestLoader().loadTestsFromTestCase(M2CryptoCrypterTest),
     unittest.TestLoader().loadTestsFromTestCase(PyCryptoM2CryptoInteropTest)
    ])

  return alltests

if __name__ == "__main__":
  unittest.main(defaultTest='suite')
