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

import cStringIO as StringIO
import os
import random
import unittest

from keyczar import errors
from keyczar import keyczar
from keyczar import readers
from keyczar import util
from keyczar import keys
from keyczar import keyinfo

TEST_DATA = os.path.realpath(os.path.join(os.getcwd(), "..", "..", "testdata"))

class BaseCrypterTest(unittest.TestCase):
  
  # read/write sizes 
  SIZE_ALL = 0
  SIZE_ONE = -1
  SIZE_RANDOM = -2

  ALL_SIZES = (SIZE_ALL,
               SIZE_ONE,
               SIZE_RANDOM)

  def setUp(self):
    self.input_data = "This is some test data"
    self.random_input_data = os.urandom(random.randrange(
      util.DEFAULT_STREAM_BUFF_SIZE * 2 + 1,
      10000))
    self.random_input_data_len = len(self.random_input_data)
    self.random_buff_size = random.randrange(1, self.random_input_data_len)
    self.ALL_BUFFER_SIZES = (util.DEFAULT_STREAM_BUFF_SIZE, 
                             999, 
                             self.random_buff_size, 
                             -1, 
                            )
  
  def __writeToStream(self, stream, data, size_mode=SIZE_ALL):
    """Helper to write to a stream with varying size writes"""
    if size_mode == self.SIZE_ALL:
      stream.write(data)
    else:
      if size_mode == self.SIZE_ONE:
        len_to_write = 1
      elif size_mode == self.SIZE_RANDOM:
        len_to_write = random.randrange(len(data) / 3, (len(data) - 1))
      else:
        assert 0, 'Invalid size_mode:%d' %size_mode
      for c in map(None, *(iter(data),) * len_to_write):
        stream.write(''.join([x for x in c if x]))
    stream.flush()

  def __readFromStream(self, stream, size_mode=SIZE_ALL):
    """Helper to read from a stream in varying size chunks"""
    result = ''
    if size_mode == self.SIZE_ALL:
      read_data = True
      while read_data or read_data is None:
        read_data = stream.read()
        if read_data:
          result += read_data
    else:
      if size_mode == self.SIZE_ONE:
        len_to_read = 1
      elif size_mode == self.SIZE_RANDOM:
        len_to_read = random.randrange(1, 1000)
      else:
        assert 0, 'Invalid size_mode:%d' %size_mode
      read_data = True
      while read_data or read_data is None:
        read_data = stream.read(len_to_read)
        if read_data:
          result += read_data
    stream.close()
    return result

  def __simulateReflow(self, data):
    """Helper to simulate reflowing of data"""
    endings = ['\n', '\r', '\r\n']
    reflowed_data = ''
    for c in map(None, *(iter(data),) * 5):
      d = ''.join([x for x in c if x])
      reflowed_data += '%s%s' %(random.choice(endings), d)
    return reflowed_data

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
  
  def __testDecryptReflowed(self, subdir, reader=None):
    path = os.path.join(TEST_DATA, subdir)
    if reader:
      crypter = keyczar.Crypter(reader)
    else:
      crypter = keyczar.Crypter.Read(path)
    active_ciphertext = util.ReadFile(os.path.join(path, "1.out"))

    reflowed_active_ciphertext = self.__simulateReflow(active_ciphertext)
    active_decrypted = crypter.Decrypt(reflowed_active_ciphertext)
    self.assertEquals(self.input_data, active_decrypted)

    primary_ciphertext = util.ReadFile(os.path.join(path, "2.out"))
    reflowed_primary_ciphertext = self.__simulateReflow(primary_ciphertext)
    primary_decrypted = crypter.Decrypt(reflowed_primary_ciphertext)
    self.assertEquals(self.input_data, primary_decrypted)

  def __testDecryptStream(self, subdir, reader, input_data, buffer_size,
                          size_mode, stream_source):
    """NOTE: input_data ignored here as we don't have a valid ".out" for
    random data"""
    path = os.path.join(TEST_DATA, subdir)
    if reader:
      crypter = keyczar.Crypter(reader)
    else:
      crypter = keyczar.Crypter.Read(path)
    active_ciphertext = util.ReadFile(os.path.join(path, "1.out"))
    if stream_source is None:
      decoder = None
      active_ciphertext = util.Base64WSDecode(active_ciphertext)
    else:
      decoder = util.IncrementalBase64WSStreamReader
    decryption_stream = crypter.CreateDecryptingStreamReader(
      StringIO.StringIO(active_ciphertext), 
      decoder=decoder,
      buffer_size=buffer_size)
    plaintext = self.__readFromStream(decryption_stream, size_mode)
    self.assertEquals(self.input_data, plaintext,
                      'Active not equals for buffer:%d, mode:%d, src:%s' %(
                        buffer_size,
                        size_mode,
                        stream_source
                      ))

    primary_ciphertext = util.ReadFile(os.path.join(path, "2.out"))
    if stream_source is None:
      primary_ciphertext = util.Base64WSDecode(primary_ciphertext)
    decryption_stream = crypter.CreateDecryptingStreamReader(
      StringIO.StringIO(primary_ciphertext), 
      decoder=decoder,
      buffer_size=buffer_size)
    plaintext = self.__readFromStream(decryption_stream, size_mode)
    self.assertEquals(self.input_data, plaintext,
                      'Primary not equals for buffer:%d, mode:%d, src:%s' %(
                        buffer_size,
                        size_mode,
                        stream_source
                      ))

  def __testEncryptAndDecrypt(self, subdir):
    crypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, subdir))
    ciphertext = crypter.Encrypt(self.input_data)
    plaintext = crypter.Decrypt(ciphertext)
    self.assertEquals(self.input_data, plaintext)

    reflowed_ciphertext = self.__simulateReflow(ciphertext)
    plaintext = crypter.Decrypt(reflowed_ciphertext)
    self.assertEquals(self.input_data, plaintext)

    self.__testEncryptAndDecryptUnencoded(subdir)
  
  def __testEncryptAndDecryptUnencoded(self, subdir):
    crypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, subdir))
    ciphertext = crypter.Encrypt(self.input_data, encoder=None)
    try:
        plaintext = crypter.Decrypt(ciphertext)
    except:
        pass
    plaintext = crypter.Decrypt(ciphertext, decoder=None)
    self.assertEquals(self.input_data, plaintext)

  def __testStandardEncryptAndStreamDecrypt(self, subdir, 
                                            input_data,
                                            buffer_size,
                                            size_mode,
                                            stream_source
                                           ):
    crypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, subdir))
    ciphertext = crypter.Encrypt(input_data)
    ciphertext_stream = StringIO.StringIO(ciphertext)

    if stream_source is None:
      decoder = None
      ciphertext_stream = StringIO.StringIO(util.Base64WSDecode(ciphertext))
    else:
      decoder = util.IncrementalBase64WSStreamReader
    decryption_stream = crypter.CreateDecryptingStreamReader(
      ciphertext_stream, 
      decoder=decoder,
      buffer_size=buffer_size)
    plaintext = self.__readFromStream(decryption_stream, size_mode)
    self.assertEquals(len(input_data), len(plaintext), 
                      'Wrong length for buffer:%d, mode:%d' %(buffer_size,
                                                              size_mode))
    self.assertEquals(input_data, plaintext,
                      'Not equals for buffer:%d, mode:%d' %(buffer_size,
                                                            size_mode))

  def __testStreamEncryptAndStandardDecrypt(self, subdir, 
                                            input_data,
                                            buffer_size,
                                            size_mode,
                                            stream_source
                                           ):
    crypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, subdir))
    ciphertext_stream = StringIO.StringIO()
    if stream_source is None:
      encoder = None
      decoder = None
    else:
      encoder = util.IncrementalBase64WSStreamWriter
      decoder = util.Base64WSDecode
    encryption_stream = crypter.CreateEncryptingStreamWriter(
      ciphertext_stream, 
      encoder=encoder)
    self.__writeToStream(encryption_stream, input_data, size_mode)
    encryption_stream.close()
    ciphertext = ciphertext_stream.getvalue()
    plaintext = crypter.Decrypt(ciphertext, decoder=decoder)
    self.assertEquals(len(input_data), len(plaintext), 
                      'Wrong length for buffer:%d, mode:%d' %(buffer_size,
                                                              size_mode))
    self.assertEquals(input_data, plaintext,
                      'Not equals for buffer:%d, mode:%d' %(buffer_size,
                                                            size_mode))

  def __testStreamEncryptAndStreamDecrypt(self, subdir,
                                          input_data,
                                          buffer_size,
                                          size_mode,
                                          stream_source
                                         ):
    crypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, subdir))
    ciphertext_stream = StringIO.StringIO()
    if stream_source is None:
      encoder = None
      decoder = None
    else:
      encoder = util.IncrementalBase64WSStreamWriter
      decoder = util.IncrementalBase64WSStreamReader

    encryption_stream = crypter.CreateEncryptingStreamWriter(
      ciphertext_stream, 
      encoder=encoder)
    self.__writeToStream(encryption_stream, input_data, size_mode)
    encryption_stream.close()
    ciphertext_stream.reset()

    decryption_stream = crypter.CreateDecryptingStreamReader(
      ciphertext_stream, 
      decoder=decoder,
      buffer_size=buffer_size)
    plaintext = self.__readFromStream(decryption_stream, size_mode)
    self.assertEquals(len(input_data), len(plaintext), 
                      'Wrong length for buffer:%d, mode:%d' %(buffer_size,
                                                              size_mode))
    self.assertEquals(input_data, plaintext,
                      'Not equals for buffer:%d, mode:%d' %(buffer_size,
                                                            size_mode))
  
  def __testAllModesAndBufferSizes(self, fn, params):
    for buff_size in self.ALL_BUFFER_SIZES:
      for mode in self.ALL_SIZES:
        for data in [self.input_data, 
                     self.random_input_data,
                     self.__simulateReflow(self.random_input_data)
                    ]:
          for stream_source in ['default', None]:
            all_params = list(params) + [data, buff_size, mode, stream_source]
            fn(*all_params)

  def testRsaDecrypt(self):
    self.__testDecrypt("rsa")
    self.__testDecryptReflowed("rsa")
  
  def testRsaEncryptAndDecrypt(self):
    self.__testEncryptAndDecrypt("rsa")
  
  def testAesDecrypt(self):
    self.__testDecrypt("aes")
    self.__testDecryptReflowed("aes")

    self.__testAllModesAndBufferSizes(self.__testDecryptStream, ("aes",
                                                                 None,)) 
  
  def testAesEncryptedKeyDecrypt(self):
    file_reader = readers.FileReader(os.path.join(TEST_DATA, "aes-crypted"))
    key_decrypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, "aes"))
    reader = readers.EncryptedReader(file_reader, key_decrypter)
    self.__testDecrypt("aes-crypted", reader)
    self.__testDecryptReflowed("aes-crypted", reader)

    self.__testAllModesAndBufferSizes(self.__testDecryptStream,
                                      ("aes-crypted", reader,))
    
  def testAesEncryptAndDecrypt(self):
    self.__testEncryptAndDecrypt("aes")

  def testAesStandardEncryptAndStreamDecryptInterop(self):
    self.__testAllModesAndBufferSizes(
        self.__testStandardEncryptAndStreamDecrypt,
        ("aes",))

  def testAesStreamEncryptAndStandardDecryptInterop(self):
    self.__testAllModesAndBufferSizes(
        self.__testStreamEncryptAndStandardDecrypt,
        ("aes",))

  def testAesStreamEncryptAndStreamDecryptInterop(self):
    self.__testAllModesAndBufferSizes(
        self.__testStreamEncryptAndStreamDecrypt,
        ("aes",))

  def testBadAesCiphertexts(self):
    crypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, "aes"))
    ciphertext = util.Base64WSDecode(crypter.Encrypt(self.input_data))
    bad = util.Base64WSEncode(chr(0))
    char = chr(ord(ciphertext[2]) ^ 44) 
    ciphertext = util.Base64WSEncode(ciphertext[:2]+char+ciphertext[3:])
    self.assertRaises(errors.ShortCiphertextError, crypter.Decrypt, bad)
    self.assertRaises(errors.KeyNotFoundError, crypter.Decrypt, ciphertext)
  
  def testBadAesCiphertextsStream(self):
    crypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, "aes"))
    ciphertext = util.Base64WSDecode(crypter.Encrypt(self.input_data))  
    bad = util.Base64WSEncode(chr(0))
    char = chr(ord(ciphertext[2]) ^ 44)  
    ciphertext = util.Base64WSEncode(ciphertext[:2]+char+ciphertext[3:])

    try:
      stream = StringIO.StringIO(bad)
      decryption_stream = crypter.CreateDecryptingStreamReader(stream)
      self.__readFromStream(decryption_stream)
    except errors.ShortCiphertextError:
      pass

    try:
      stream = StringIO.StringIO(ciphertext)
      decryption_stream = crypter.CreateDecryptingStreamReader(stream)
      self.__readFromStream(decryption_stream)
    except errors.KeyNotFoundError:
      pass
  
  def testStreamDecryptHandlesIOModuleBlockingNoneReturned(self):
    """
    Test for input streams that conform to the blocking I/O module spec, i.e.
    read() returns None to indicate no data available, but not EOF
    """
    crypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, 'aes'))
    ciphertext = crypter.Encrypt(self.input_data)

    class PseudoBlockingStream(object):
      """
      A 'stream' that blocks every 2nd call to read() to simultate blocking i/o
      """

      def __init__(self, string):
        self.current_posn = 0
        self.string = string
        self.return_none = False

      def read(self, size=-1):
        result = None
        start = self.current_posn
        if not self.return_none:
          if size < 0:
            end = size 
            self.current_posn = len(self.string)
          else:
            end = (start + size)
            self.current_posn = end
          result = self.string[start:end]
        else:
          if start > len(self.string):
            result = ''

        self.return_none = not self.return_none
        return result

    decryption_stream = crypter.CreateDecryptingStreamReader(
      PseudoBlockingStream(ciphertext))
    result = self.__readFromStream(decryption_stream, size_mode=self.SIZE_ALL)
    self.assertEquals(self.input_data, result)

  def testStreamDecryptHandlesIOModuleBlockingExceptionRaised(self):
    """
    Test for input streams that conform to the blocking I/O module spec wrt
    buffered blocking, i.e. if the underlying raw stream is in non blocking-mode,
    a BlockingIOError is raised indicate no data available, but not EOF
    """
    crypter = keyczar.Crypter.Read(os.path.join(TEST_DATA, 'aes'))
    ciphertext = crypter.Encrypt(self.input_data)

    class PseudoBlockingStream(object):
      """
      A 'stream' that raises BlockingIOError every 2nd call to read() to
      simultate buffered blocking
      """

      def __init__(self, string):
        self.current_posn = 0
        self.string = string
        self.raise_exception = True 

      def read(self, size=-1):
        result = None
        start = self.current_posn
        if not self.raise_exception:
          if size < 0:
            end = size 
            self.current_posn = len(self.string)
          else:
            end = (start + size)
            self.current_posn = end
          result = self.string[start:end]
        else:
          if start > len(self.string):
            result = ''
          else:
            self.raise_exception = False
            raise util.BlockingIOError(1, 'Dummy error', self.current_posn)

        self.raise_exception = not self.raise_exception
        return result

    decryption_stream = crypter.CreateDecryptingStreamReader(
      PseudoBlockingStream(ciphertext))
    result = self.__readFromStream(decryption_stream, size_mode=self.SIZE_ALL)
    self.assertEquals(self.input_data, result)

  def tearDown(self):
    self.input_data = None
    self.random_input_data = None
    self.random_input_data_len = 0
    self.random_buff_size = 0
  
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
