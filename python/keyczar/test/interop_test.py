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
Consolidated Testcases to test behavior of Keyczar Crypters/Signers of
 other implementations.

@author: arkajit.dey@gmail.com (Arkajit Dey)

1/2013 - Combined from other tests for different platform 
         data by Jay Tuley (jay+code@tuley.name)
"""
from __future__ import absolute_import

import os
import unittest
import datetime

from keyczar import keyczar
from keyczar import util

class BaseInteropTest(unittest.TestCase):
  def __init__(self, imp, methodname='runTest'):
    unittest.TestCase.__init__(self, methodname)
    self.TEST_DATA = os.path.realpath(os.path.join(os.getcwd(), 
                      "test-data", "interop-data", imp+"_data"))
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

  def __testDecryptSizes(self, subdir, size):
    path = os.path.join(self.TEST_DATA, subdir) +"-size"
    crypter = keyczar.Crypter.Read(path)
    active_ciphertext = util.ReadFile(os.path.join(path, size + ".out"))
    active_decrypted = crypter.Decrypt(active_ciphertext)
    self.assertEqual(self.input, active_decrypted)

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

  def __readGoldenOutputSizes(self, subdir, size, public=False):
    path = os.path.join(self.TEST_DATA, subdir)
    if not public:
      czar = keyczar.Verifier.Read(path)
    else:
      czar = keyczar.Verifier.Read(os.path.join(self.TEST_DATA, 
        subdir+".public"))
    active_sig = util.ReadFile(os.path.join(path, size + ".out"))
    return (czar, active_sig)

  def __testVerify(self, subdir):
    (verifier, active_sig, primary_sig) = self.__readGoldenOutput(subdir)
    self.assertTrue(verifier.Verify(self.input, active_sig))
    self.assertTrue(verifier.Verify(self.input, primary_sig))

  def __testVerifySizes(self, subdir, size):
    (verifier, active_sig) = self.__readGoldenOutputSizes(subdir+"-size", size)
    self.assertTrue(verifier.Verify(self.input, active_sig))
  
  def __testPublicVerify(self, subdir):
    (pubverifier, active_sig, primary_sig) = self.__readGoldenOutput(subdir,
                                                                         True)
    self.assertTrue(pubverifier.Verify(self.input, active_sig))
    self.assertTrue(pubverifier.Verify(self.input, primary_sig))

  def __testPublicVerifySizes(self, subdir, size):
    (pubverifier, active_sig) = self.__readGoldenOutputSizes(subdir+"-size", 
                                                                    size, True)
    self.assertTrue(pubverifier.Verify(self.input, active_sig))

  def testAes(self):
    self.__testDecrypt("aes")

  def testAes128(self):
    self.__testDecryptSizes("aes","128")

  def testAes192(self):
    self.__testDecryptSizes("aes","192")

  def testAes256(self):
    self.__testDecryptSizes("aes","256")

  def testRsa(self):
    self.__testDecrypt("rsa")

  def testRsa1024(self):
    self.__testDecryptSizes("rsa","1024")

  def testRsa2048(self):
    self.__testDecryptSizes("rsa","2048")

  def testRsa4096(self):
    self.__testDecryptSizes("rsa","4096")

  def testHmacVerify(self):
    self.__testVerify("hmac")

  def testDsaVerify(self):
    self.__testVerify("dsa")

  def testDsaPublicVerify(self):
    self.__testPublicVerify("dsa")

  def testRsaVerify(self):
    self.__testVerify("rsa-sign")

  def testRsaVerify1024(self):
    self.__testVerifySizes("rsa-sign","1024")

  def testRsaVerify2048(self):
    self.__testVerifySizes("rsa-sign","2048")

  def testRsaVerify4096(self):
    self.__testVerifySizes("rsa-sign","4096")

  def testRsaPublicVerify(self):
    self.__testPublicVerify("rsa-sign")

  def testRsaPublicVerify1024(self):
    self.__testPublicVerifySizes("rsa-sign","1024")

  def testRsaPublicVerify2048(self):
    self.__testPublicVerifySizes("rsa-sign","2048")

  def testRsaPublicVerify4096(self):
    self.__testPublicVerifySizes("rsa-sign","4096")

class FullInteropTest(BaseInteropTest):
  def __init__(self, imp, methodname='runTest'):
    BaseInteropTest.__init__(self, imp, methodname)

  def __testSessionDecrypt(self, subdir):
    path = os.path.join(self.TEST_DATA, subdir)
    material = util.ReadFile(os.path.join(path, "2.session.material"))
    ciphertext = util.ReadFile(os.path.join(path, "2.session.ciphertext"))
    crypter = keyczar.Crypter.Read(path)
    session = keyczar.SessionDecrypter(crypter, material)
    decrypted = session.Decrypt(ciphertext)
    self.assertEqual(self.input, decrypted)

  def __testSignedSessionDecrypt(self, subdir, signsubdir):
    path = os.path.join(self.TEST_DATA, subdir)
    signpath = os.path.join(self.TEST_DATA, signsubdir)
    material = util.ReadFile(os.path.join(path, "2.signedsession.material"))
    ciphertext = util.ReadFile(os.path.join(path, "2.signedsession.ciphertext"))
    crypter = keyczar.Crypter.Read(path)
    verifier = keyczar.Verifier.Read(signpath)
    session = keyczar.SignedSessionDecrypter(crypter, verifier, material)
    decrypted = session.Decrypt(ciphertext)
    self.assertEqual(self.input, decrypted)


  def __testVerifyAttached(self, subdir, secret="", public=False):
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

  def __testVerifyTimeout(self, subdir, expired=False, public=False):
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

  def __testVerifyUnversioned(self, subdir, public=False):
    path = os.path.join(self.TEST_DATA, subdir)
    verifypath = path
    if public:
      verifypath = path +".public"
    sig = util.ReadFile(os.path.join(path, "2.unversioned"))
    verifier = keyczar.UnversionedVerifier.Read(verifypath)
    self.assertTrue(verifier.Verify(self.input, sig))

  def testRsaSessionDecrypt(self):
    self.__testSessionDecrypt("rsa")

  def testRsaDsaSignedSessionDecrypt(self):
    self.__testSignedSessionDecrypt("rsa", "dsa")

  def testRsaDsaPublicSignedSessionDecrypt(self):
    self.__testSignedSessionDecrypt("rsa", "dsa.public")

  def testHmacVerifyAttached(self):
    self.__testVerifyAttached("hmac")

  def testHmacVerifySecretAttached(self):
    self.__testVerifyAttached("hmac", "secret")

  def testHmacVerifyTimeoutSuccess(self):
    self.__testVerifyTimeout("hmac")

  def testHmacVerifyTimeoutFail(self):
    self.__testVerifyTimeout("hmac", expired=True)

  def testHmacVerifyUnversioned(self):
    self.__testVerifyUnversioned("hmac")

  def testDsaVerifyAttached(self):
    self.__testVerifyAttached("dsa")

  def testDsaVerifySecretAttached(self):
    self.__testVerifyAttached("dsa", "secret")

  def testDsaVerifyTimeoutSuccess(self):
    self.__testVerifyTimeout("dsa")

  def testDsaVerifyTimeoutFail(self):
    self.__testVerifyTimeout("dsa", expired=True)

  def testDsaVerifyUnversioned(self):
    self.__testVerifyUnversioned("dsa")
          
  def testDsaPublicVerifyAttached(self):
    self.__testVerifyAttached("dsa", public=True)

  def testDsaPublicVerifySecretAttached(self):
    self.__testVerifyAttached("dsa", "secret", public=True)

  def testDsaPublicVerifyTimeoutSuccess(self):
    self.__testVerifyTimeout("dsa", public= True)

  def testDsaPublicVerifyTimeoutFail(self):
    self.__testVerifyTimeout("dsa", expired=True, public=True)

  def testDsaPublicVerifyUnversioned(self):
    self.__testVerifyUnversioned("dsa", public=True)

  def testRsaVerifyAttached(self):
    self.__testVerifyAttached("rsa-sign")

  def testRsaVerifySecretAttached(self):
    self.__testVerifyAttached("rsa-sign", "secret")

  def testRsaVerifyTimeoutSuccess(self):
    self.__testVerifyTimeout("rsa-sign")

  def testRsaVerifyTimeoutFail(self):
    self.__testVerifyTimeout("rsa-sign", expired=True)

  def testRsaVerifyUnversioned(self):
    self.__testVerifyUnversioned("rsa-sign")

  def testRsaPublicVerifyAttached(self):
    self.__testVerifyAttached("rsa-sign", public= True)

  def testRsaPublicVerifySecretAttached(self):
    self.__testVerifyAttached("rsa-sign", "secret", public=True)

  def testRsaPublicVerifyTimeoutSuccess(self):
    self.__testVerifyTimeout("rsa-sign", public= True)

  def testRsaPublicVerifyTimeoutFail(self):
    self.__testVerifyTimeout("rsa-sign", expired=True, public=True)
  
  def testRsaPublicVerifyUnversioned(self):
    self.__testVerifyUnversioned("rsa-sign", public=True)

class CSInteropTest(FullInteropTest):
  def __init__(self, methodname='runTest'):
    FullInteropTest.__init__(self, "cs", methodname)

class PYInteropTest(FullInteropTest):
  def __init__(self, methodname='runTest'):
    FullInteropTest.__init__(self, "py", methodname)

class PY3InteropTest(FullInteropTest):
  def __init__(self, methodname='runTest'):
    FullInteropTest.__init__(self, "py3", methodname)
      
class JInteropTest(FullInteropTest): 
  def __init__(self, methodname='runTest'):
    FullInteropTest.__init__(self, "j", methodname)

class GOInteropTest(FullInteropTest):
  def __init__(self, methodname='runTest'):
    FullInteropTest.__init__(self, "go", methodname)

def suite():
  suite = unittest.TestSuite()
  suite.addTests(unittest.TestLoader().loadTestsFromTestCase(CSInteropTest))
  suite.addTests(unittest.TestLoader().loadTestsFromTestCase(JInteropTest))
  suite.addTests(unittest.TestLoader().loadTestsFromTestCase(PYInteropTest))
  suite.addTests(unittest.TestLoader().loadTestsFromTestCase(PY3InteropTest))
  suite.addTests(unittest.TestLoader().loadTestsFromTestCase(GOInteropTest))
  return suite

if __name__ == "__main__":
  unittest.main(defaultTest='suite')
