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
import random
import cStringIO as StringIO
import unittest

from keyczar import errors
from keyczar import keyczar
from keyczar import readers
from keyczar import util
from keyczar import keys

TEST_DATA = os.path.realpath(os.path.join(os.getcwd(), "..", "testdata"))

class CrypterTest(unittest.TestCase):
  
  # write modes
  WRITE_ALL = 0
  WRITE_ONE = -1
  WRITE_RANDOM = -2

  ALL_MODES = (WRITE_ALL,
               WRITE_ONE,
               WRITE_RANDOM)

  def setUp(self):
    self.input_data = "This is some test data"
    # generate some longer random data
    self.random_input_data = os.urandom(random.randrange(
      util.DEFAULT_STREAM_BUFF_SIZE*2 + 1,
      50000))
    self.random_input_data_len = len(self.random_input_data)
    # use a random buffer size that is less than the input length
    self.random_buff_size = random.randrange(1, self.random_input_data_len)
    self.ALL_BUFFER_SIZES = (util.DEFAULT_STREAM_BUFF_SIZE, # default
                             999, # smaller
                             self.random_buff_size, # er, random
                            )
  
  def __writeToStream(self, stream, data, write_mode=WRITE_ALL):
    """Helper to write to a stream with varying size writes"""
    if write_mode == self.WRITE_ALL:
      stream.write(data)
    else:
      if write_mode == self.WRITE_ONE:
        len_to_write = 1
      elif write_mode == self.WRITE_RANDOM:
        len_to_write = random.randrange(len(data)/3, (len(data) - 1))
      else:
        assert 0, 'Invalid write_mode:%d' %write_mode
      # write out in groups of size len_to_write
      for c in map(None, *(iter(data),) * len_to_write):
        stream.write(''.join([x for x in c if x]))

  def __testDecrypt(self, subdir, reader=None):
    path = os.path.join(TEST_DATA, subdir)
    if reader:
      crypter = keyczar.Crypter(reader)
    else:
      crypter = keyczar.Crypter.Read(path)
    active_ciphertext = util.ReadFile(os.path.join(path, "1.out"))
    primary_ciphertext = util.ReadFile(os.path.join(path, "2.out"))
    active_decrypted = crypter.Decrypt(active_ciphertext)
    self.assertEquals(self.input_data, active_decrypted)
    primary_decrypted = crypter.Decrypt(primary_ciphertext)
    self.assertEquals(self.input_data, primary_decrypted)
  
  def __testDecryptStream(self, subdir, reader, input_data, buffer_size, write_mode):
    """NOTE: input_data ignored here as we don't have a valid ".out" for
    random data"""
    path = os.path.join(TEST_DATA, subdir)
    if reader:
      crypter = keyczar.Crypter(reader)
    else:
      crypter = keyczar.Crypter.Read(path)
    # check active key
    active_ciphertext = util.ReadFile(os.path.join(path, "1.out"))
    active_decrypted_stream = StringIO.StringIO()
    decryption_stream = crypter.CreateDecryptingStream(active_decrypted_stream,
                                                      buffer_size=buffer_size)
    self.__writeToStream(decryption_stream, active_ciphertext, write_mode)
    decryption_stream.close()
    self.assertEquals(self.input_data, active_decrypted_stream.getvalue(),
                      'Not equals for buffer:%d, mode:%d' %(buffer_size,
                                                            write_mode))

    # check primary key
    primary_ciphertext = util.ReadFile(os.path.join(path, "2.out"))
    primary_decrypted_stream = StringIO.StringIO()
    decryption_stream = crypter.CreateDecryptingStream(primary_decrypted_stream,
                                                      buffer_size=buffer_size)
    self.__writeToStream(decryption_stream, primary_ciphertext, write_mode)
    decryption_stream.close()
    self.assertEquals(self.input_data, primary_decrypted_stream.getvalue(),
                      'Not equals for buffer:%d, mode:%d' %(buffer_size,
                                                            write_mode))

  def __testEncryptAndDecrypt(self, subdir):
    crypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, subdir))
    ciphertext = crypter.Encrypt(self.input_data)
    plaintext = crypter.Decrypt(ciphertext)
    self.assertEquals(self.input_data, plaintext)
  
  def __testStandardEncryptAndStreamDecrypt(self, subdir, 
                                            input_data,
                                            buffer_size,
                                            write_mode):
    crypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, subdir))
    ciphertext = crypter.Encrypt(input_data)
    plaintext_stream = StringIO.StringIO()

    decryption_stream = crypter.CreateDecryptingStream(plaintext_stream,
                                                       buffer_size=buffer_size)
    self.__writeToStream(decryption_stream, ciphertext, write_mode)
    decryption_stream.close()
    plaintext = plaintext_stream.getvalue()
    self.assertEquals(len(input_data), len(plaintext), 
                      'Wrong length for buffer:%d, mode:%d' %(buffer_size,
                                                              write_mode))
    self.assertEquals(input_data, plaintext,
                      'Not equals for buffer:%d, mode:%d' %(buffer_size,
                                                            write_mode))

  def __testStreamEncryptAndStandardDecrypt(self, subdir, 
                                            input_data,
                                            buffer_size,
                                            write_mode):
    crypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, subdir))
    ciphertext_stream = StringIO.StringIO()
    encryption_stream = crypter.CreateEncryptingStream(ciphertext_stream,
                                                       buffer_size=buffer_size)
    self.__writeToStream(encryption_stream, input_data, write_mode)
    encryption_stream.close()
    ciphertext = ciphertext_stream.getvalue()
    plaintext = crypter.Decrypt(ciphertext)
    self.assertEquals(len(input_data), len(plaintext), 
                      'Wrong length for buffer:%d, mode:%d' %(buffer_size,
                                                              write_mode))
    self.assertEquals(input_data, plaintext,
                      'Not equals for buffer:%d, mode:%d' %(buffer_size,
                                                            write_mode))
  
  def __testStreamEncryptAndStreamDecrypt(self, subdir,
                                          input_data,
                                          buffer_size,
                                          write_mode,
                                         ):
    #input_data = self.input_data
    crypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, subdir))
    ciphertext_stream = StringIO.StringIO()
    encryption_stream = crypter.CreateEncryptingStream(ciphertext_stream,
                                                       buffer_size=buffer_size)
    self.__writeToStream(encryption_stream, input_data, write_mode)
    encryption_stream.close()
    ciphertext_stream.reset()
    plaintext_stream = StringIO.StringIO()

    decryption_stream = crypter.CreateDecryptingStream(plaintext_stream,
                                                       buffer_size=buffer_size)
    self.__writeToStream(decryption_stream, ciphertext_stream.getvalue(), write_mode)
    decryption_stream.close()
    plaintext = plaintext_stream.getvalue()
    self.assertEquals(len(input_data), len(plaintext), 
                      'Wrong length for buffer:%d, mode:%d' %(buffer_size,
                                                              write_mode))
    self.assertEquals(input_data, plaintext,
                      'Not equals for buffer:%d, mode:%d' %(buffer_size,
                                                            write_mode))
  
  def __testAllModesAndBufferSizes(self, fn, params):
    for buff_size in self.ALL_BUFFER_SIZES:
      for mode in self.ALL_MODES:
        for data in [self.input_data, self.random_input_data]:
          all_params = list(params) + [data, buff_size, mode]
          fn(*all_params)

  def testRsaDecrypt(self):
    self.__testDecrypt("rsa")
  
  def testRsaEncryptAndDecrypt(self):
    self.__testEncryptAndDecrypt("rsa")
  
  def testAesDecrypt(self):
    self.__testDecrypt("aes")

    # test streaming decryption for all combinations
    self.__testAllModesAndBufferSizes(self.__testDecryptStream, ("aes",
                                                                 None,)) 
  
  def testAesEncryptedKeyDecrypt(self):
    file_reader = readers.FileReader(os.path.join(TEST_DATA, "aes-crypted"))
    key_decrypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, "aes"))
    reader = readers.EncryptedReader(file_reader, key_decrypter)
    self.__testDecrypt("aes-crypted", reader)

    # test streaming decryption for all combinations
    self.__testAllModesAndBufferSizes(self.__testDecryptStream,
                                      ("aes-crypted", reader,))
    
  def testAesEncryptAndDecrypt(self):
    self.__testEncryptAndDecrypt("aes")

  def testAesStandardEncryptAndStreamDecryptInterop(self):
    # test streaming decryption for all combinations
    self.__testAllModesAndBufferSizes(self.__testStandardEncryptAndStreamDecrypt,
                                      ("aes",))

  def testAesStreamEncryptAndStandardDecryptInterop(self):
    # test streaming encryption for all combinations
    self.__testAllModesAndBufferSizes(self.__testStreamEncryptAndStandardDecrypt,
                                      ("aes",))

  def testAesStreamEncryptAndStreamDecryptInterop(self):
    # test streaming encryption/decryption for all combinations
    self.__testAllModesAndBufferSizes(self.__testStreamEncryptAndStreamDecrypt,
                                      ("aes",))

  def testBadAesCiphertexts(self):
    crypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, "aes"))
    ciphertext = util.Decode(crypter.Encrypt(self.input_data))  # in bytes
    bad = util.Encode(chr(0))
    char = chr(ord(ciphertext[2]) ^ 44)  # Munge key hash info in ciphertext
    ciphertext = util.Encode(ciphertext[:2]+char+ciphertext[3:])
    self.assertRaises(errors.ShortCiphertextError, crypter.Decrypt, bad)
    self.assertRaises(errors.KeyNotFoundError, crypter.Decrypt, ciphertext)
  
  def testBadAesCiphertextsStream(self):
    crypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, "aes"))
    ciphertext = util.Decode(crypter.Encrypt(self.input_data))  # in bytes
    bad = util.Encode(chr(0))
    char = chr(ord(ciphertext[2]) ^ 44)  # Munge key hash info in ciphertext
    ciphertext = util.Encode(ciphertext[:2]+char+ciphertext[3:])

    try:
      decryption_stream = crypter.CreateDecryptingStream(StringIO.StringIO())
      self.__writeToStream(decryption_stream, bad)
      decryption_stream.close()
    except errors.ShortCiphertextError:
      # expected
      pass

    try:
      decryption_stream = crypter.CreateDecryptingStream(StringIO.StringIO())
      self.__writeToStream(decryption_stream, ciphertext)
      decryption_stream.close()
    except errors.KeyNotFoundError:
      # expected
      pass
  
  def tearDown(self):
    self.input_data = None
  
def suite():
  alltests = unittest.TestSuite(
    [unittest.TestLoader().loadTestsFromTestCase(CrypterTest),
    ])

  return alltests

if __name__ == "__main__":
  unittest.main(defaultTest='suite')
