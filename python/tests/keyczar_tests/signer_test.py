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

import os
import unittest

from keyczar import errors
from keyczar import keyczar
from keyczar import util

TEST_DATA = os.path.realpath(os.path.join(os.getcwd(), "..", "..", "testdata"))

class SignerTest(unittest.TestCase):

  def setUp(self):
    self.input = "This is some test data"

  def __unencodedSignInput(self, subdir):
    signer = keyczar.Signer.Read(os.path.join(TEST_DATA, subdir))
    sig = signer.Sign(self.input, None)
    return (signer, sig)

  def __unencodedUnversionedSignInput(self, subdir):
    unversioned_signer = keyczar.UnversionedSigner.Read(os.path.join(TEST_DATA, subdir))
    sig = unversioned_signer.Sign(self.input, None)
    return (unversioned_signer, sig)

  def __unencodedAttachedSignInput(self, subdir, nonce):
    signer = keyczar.Signer.Read(os.path.join(TEST_DATA, subdir))
    attached_sig = signer.AttachedSign(self.input, nonce, None)
    return (signer, attached_sig)


  def __signInput(self, subdir):
    signer = keyczar.Signer.Read(os.path.join(TEST_DATA, subdir))
    sig = signer.Sign(self.input)
    return (signer, sig)

  def __unversionedSignInput(self, subdir):
    unversioned_signer = keyczar.UnversionedSigner.Read(os.path.join(TEST_DATA, subdir))
    sig = unversioned_signer.Sign(self.input)
    return (unversioned_signer, sig)

  def __attachedSignInput(self, subdir, nonce):
    signer = keyczar.Signer.Read(os.path.join(TEST_DATA, subdir))
    attached_sig = signer.AttachedSign(self.input, nonce)
    return (signer, attached_sig)

  def __readGoldenOutput(self, subdir, verifier=False, public=False):
    path = os.path.join(TEST_DATA, subdir)
    if verifier and not public:
      czar = keyczar.Verifier.Read(path)
    elif verifier and public:
      czar = keyczar.Verifier.Read(os.path.join(TEST_DATA, subdir+".public"))
    else:
      czar = keyczar.Signer.Read(path)
    active_sig = util.ReadFile(os.path.join(path, "1.out"))
    primary_sig = util.ReadFile(os.path.join(path, "2.out"))
    return (czar, active_sig, primary_sig)

  def __testSignAndVerify(self, subdir):
    (signer, sig) = self.__signInput(subdir)
    self.assertTrue(signer.Verify(self.input, sig))
    self.assertFalse(signer.Verify("Wrong string", sig))

  def __testUnversionedSignAndVerify(self, subdir):
    (unversioned_signer, sig) = self.__unversionedSignInput(subdir)
    self.assertTrue(unversioned_signer.Verify(self.input, sig))
    self.assertFalse(unversioned_signer.Verify("Wrong string", sig))

  def __testAttachedSignAndVerify(self, subdir):
    (signer, attached_sig) = self.__attachedSignInput(subdir, "nonce")
    self.assertEquals(self.input, signer.AttachedVerify(attached_sig, "nonce"))

    # Changing nonce should make it fail.
    self.assertFalse(signer.AttachedVerify(attached_sig, "dunce"))

    # Changing signature should make it fail.
    bad_sig = self.__modifyByteString(attached_sig, -5)
    self.assertFalse(signer.AttachedVerify(bad_sig, "nonce"))

    # Changing data should make it fail.
    bad_data = self.__modifyByteString(attached_sig, keyczar.HEADER_SIZE + 4)
    self.assertFalse(signer.AttachedVerify(bad_data, "nonce"))

  def __modifyByteString(self, string, offset):
    decoded = util.Base64WSDecode(string)
    modified_char = chr(ord(decoded[offset]) ^ 0xFF)
    return util.Base64WSEncode(decoded[:offset] + modified_char + decoded[offset+1:])

  def __testSignerVerify(self, subdir):
    (signer, active_sig, primary_sig) = self.__readGoldenOutput(subdir)
    self.assertTrue(signer.Verify(self.input, active_sig))
    self.assertTrue(signer.Verify(self.input, primary_sig))

  def __testVerify(self, subdir):
    (verifier, active_sig, primary_sig) = self.__readGoldenOutput(subdir, True)
    self.assertTrue(verifier.Verify(self.input, active_sig))
    self.assertTrue(verifier.Verify(self.input, primary_sig))

  def __testPublicVerify(self, subdir):
    (pubverifier, active_sig, primary_sig) = self.__readGoldenOutput(subdir,
                                                                     True, True)
    self.assertTrue(pubverifier.Verify(self.input, active_sig))
    self.assertTrue(pubverifier.Verify(self.input, primary_sig))

  def __testBadVerify(self, subdir):
    (signer, active_sig, primary_sig) = self.__readGoldenOutput(subdir)
    self.assertFalse(signer.Verify("Wrong string", active_sig))
    self.assertFalse(signer.Verify("Wrong string", primary_sig))
    self.assertFalse(signer.Verify(self.input, primary_sig[:-4]+"Junk"))

  def testHmacSignAndVerify(self):
    self.__testSignAndVerify("hmac")
    self.__testAttachedSignAndVerify("hmac")

  def testRsaSignatureLengthPadding(self):
    """
    Checks that byte strings are padded with 0s in front for small signatures.

    Generates strings of 'a's and signs them until a signature is either
    of the incorrect length or contains a \x00 byte as the first character
    """
    signer = keyczar.Signer.Read(os.path.join(TEST_DATA, "rsa-sign"))
    t = 0
    flag = True
    while flag:
      t += 1
      sig = util.Base64WSDecode(signer.Sign(t*"a"))
      assert(len(sig) == 256 + keyczar.HEADER_SIZE) # 256 = keysize in bytes
      flag = sig[keyczar.HEADER_SIZE] != chr(0)

  def testUnencodedVerify(self):
    (signer, sig) = self.__signInput("hmac")

    unencoded_sig = util.Base64WSDecode(sig)
    self.assertTrue(signer.Verify(self.input, unencoded_sig, None))
    try:
      signer.Verify(self.input, unencoded_sig)
      raise Exception("Verify should throw a Decoding error")
    except errors.Base64DecodingError, e:
      pass
    self.assertTrue(signer.Verify(self.input, sig))

  def testUnencodedSign(self):
    (signer, sig) = self.__unencodedSignInput("hmac")
    encoded_sig = util.Base64WSEncode(sig)
    self.assertTrue(signer.Verify(self.input, encoded_sig))
    self.assertTrue(signer.Verify(self.input, sig, None))

  def testUnencodedUnversionedVerify(self):
    (signer, sig) = self.__unversionedSignInput("hmac")
    unencoded_sig = util.Base64WSDecode(sig)
    self.assertTrue(signer.Verify(self.input, unencoded_sig, None))
    self.assertFalse(signer.Verify(self.input, unencoded_sig))
    self.assertFalse(signer.Verify(self.input, sig, None))
    self.assertTrue(signer.Verify(self.input, sig))

  def testUnencodedUnversionedSign(self):
    (signer, sig) = self.__unencodedUnversionedSignInput("hmac")
    encoded_sig = util.Base64WSEncode(sig)
    self.assertFalse(signer.Verify(self.input, encoded_sig, None))
    self.assertTrue(signer.Verify(self.input, encoded_sig))
    self.assertTrue(signer.Verify(self.input, sig, None))

  def testUnencodedAttachedVerify(self):
    (signer, sig) = self.__attachedSignInput("hmac", "nonce")
    unencoded_sig = util.Base64WSDecode(sig)
    self.assertTrue(signer.AttachedVerify(unencoded_sig, "nonce", None))
    try:
      signer.Verify(self.input, unencoded_sig)
      raise Exception("Verify should throw a Decoding error")
    except errors.Base64DecodingError, e:
      pass
    self.assertTrue(signer.AttachedVerify(sig, "nonce"))

  def testUnencodedAttachedSign(self):
    (signer, sig) = self.__unencodedAttachedSignInput("hmac", "nonce")
    encoded_sig = util.Base64WSEncode(sig)
    self.assertTrue(signer.AttachedVerify(encoded_sig, "nonce"))
    self.assertTrue(signer.AttachedVerify(sig, "nonce", None))

  def testHmacUnversionedSignAndVerify(self):
    self.__testUnversionedSignAndVerify("hmac")

  def testHmacVerify(self):
    self.__testSignerVerify("hmac")

  def testBadHmacVerify(self):
    self.__testBadVerify("hmac")

  def testDsaSignAndVerify(self):
    self.__testSignAndVerify("dsa")
    self.__testAttachedSignAndVerify("dsa")

  def testDsaUnversionedSignAndVerify(self):
    self.__testUnversionedSignAndVerify("dsa")

  def testDsaSignerVerify(self):
    self.__testSignerVerify("dsa")

  def testDsaVerify(self):
    self.__testVerify("dsa")

  def testDsaPublicVerify(self):
    self.__testPublicVerify("dsa")

  def testBadDsaVerify(self):
    self.__testBadVerify("dsa")

  def testRsaSignAndVerify(self):
    self.__testSignAndVerify("rsa-sign")
    self.__testAttachedSignAndVerify("rsa-sign")

  def testRsaUnversionedSignAndVerify(self):
    self.__testUnversionedSignAndVerify("rsa-sign")

  def testRsaSignerVerify(self):
    self.__testSignerVerify("rsa-sign")

  def testRsaVerify(self):
    self.__testVerify("rsa-sign")

  def testRsaPublicVerify(self):
    self.__testPublicVerify("rsa-sign")

  def testBadRsaVerify(self):
    self.__testBadVerify("rsa-sign")

  def testHmacBadSigs(self):
    (signer, sig) = self.__signInput("hmac")
    sig_bytes = util.Base64WSDecode(sig)
    self.assertRaises(errors.ShortSignatureError, signer.Verify,
                      self.input, "AB")
    bad_sig = util.Base64WSEncode(chr(23) + sig_bytes[1:])
    self.assertRaises(errors.BadVersionError, signer.Verify,
                      self.input, bad_sig)
    char = chr(ord(sig_bytes[1]) ^ 45)  # Munge key hash info in sig
    bad_sig = util.Base64WSEncode(sig_bytes[0] + char + sig_bytes[2:])
    self.assertRaises(errors.KeyNotFoundError, signer.Verify,
                      self.input, bad_sig)

  def tearDown(self):
    self.input = None

def suite():
  suite = unittest.TestSuite()
  suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SignerTest))
  return suite

if __name__ == "__main__":
  unittest.main(defaultTest='suite')
