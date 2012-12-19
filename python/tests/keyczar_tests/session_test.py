#
# Copyright 2011 Google Inc.
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
Test cases to test behavior of Keyczar Session encrypters and signers.

@author: swillden@google.com (Shawn Willden)
"""

import os
import unittest

from keyczar import keyczar
from keyczar import util
from keyczar import errors

TEST_DATA = os.path.realpath(os.path.join(os.getcwd(), "..", "..", "testdata"))


def _get_test_dir(subdir):
  return os.path.join(TEST_DATA, subdir)


class SessionEncrypterTest(unittest.TestCase):
  """
  Tests Session encryption
  """

  def setUp(self):
    self.input = "This is some test data"

  def testSessionEncryptAndDecrypt(self):
    encrypter = keyczar.Encrypter.Read(_get_test_dir("rsa"))
    session_encrypter = keyczar.SessionEncrypter(encrypter);
    session_material = session_encrypter.session_material
    ciphertext = session_encrypter.Encrypt(self.input)

    # Verify that session_material and ciphertext are base64-encoded: Decoding will fail with
    # high probability if they're not.
    util.Base64WSDecode(session_material)
    util.Base64WSDecode(ciphertext)

    crypter = keyczar.Crypter.Read(_get_test_dir("rsa"))
    session_decrypter = keyczar.SessionDecrypter(crypter, session_material)
    plaintext = session_decrypter.Decrypt(ciphertext)
    self.assertEqual(self.input, plaintext)

  def testSignedSessionEncryptAndDecrypt(self):
    encrypter = keyczar.Encrypter.Read(_get_test_dir("rsa"))
    signer = keyczar.Signer.Read(_get_test_dir("dsa"))
    session_encrypter = keyczar.SignedSessionEncrypter(encrypter, signer)
    session_material = session_encrypter.session_material
    ciphertext = session_encrypter.Encrypt(self.input)

    # Verify that session_material and ciphertext are base64-encoded: Decoding will fail with
    # high probability if they're not.
    util.Base64WSDecode(session_material)
    util.Base64WSDecode(ciphertext)

    crypter = keyczar.Crypter.Read(_get_test_dir("rsa"))
    verifier = keyczar.Verifier.Read(_get_test_dir("dsa"))
    session_decrypter = keyczar.SignedSessionDecrypter(crypter, verifier, session_material)
    plaintext = session_decrypter.Decrypt(ciphertext)
    self.assertEqual(self.input, plaintext)


def suite():
  return unittest.makeSuite(SessionEncrypterTest, 'test')
