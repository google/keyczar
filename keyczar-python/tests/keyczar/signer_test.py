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
Testcases to test behavior of Keyczar Signers.

@author: arkajit.dey@gmail.com (Arkajit Dey)
"""

from keyczar import keyczar
from keyczar import errors
from keyczar import util

import unittest
import os

TEST_DATA = os.path.realpath(os.path.join(os.getcwd(), "..", "..", "testdata"))

class SignerTest(unittest.TestCase):
  
  def setUp(self):
    self.input = "Hello Google"
  
  def __signInput(self, subdir):
    signer = keyczar.Signer.Read(os.path.join(TEST_DATA, subdir))
    sig = signer.Sign(self.input)
    return (signer, sig)
  
  def __readGoldenOutput(self, subdir, verifier=False, public=False):
    path = os.path.join(TEST_DATA, subdir)
    if verifier and not public:
      czar = keyczar.Verifier.Read(path)
    elif verifier and public:
      czar = keyczar.Verifier.Read(os.path.join(TEST_DATA, subdir+".public"))
    else:
      czar = keyczar.Signer.Read(path)
    active_sig = open(os.path.join(path, "1out")).read()
    primary_sig = open(os.path.join(path, "2out")).read()
    return (czar, active_sig, primary_sig)
  
  def __testSignAndVerify(self, subdir):
    (signer, sig) = self.__signInput(subdir)
    self.assertTrue(signer.Verify(self.input, sig))
    self.assertFalse(signer.Verify("Wrong string", sig))
  
  def __testSignerVerify(self, subdir):
    (signer, active_sig, primary_sig) = self.__readGoldenOutput(subdir)
    self.assertTrue(signer.Verify(self.input, active_sig))
    self.assertTrue(signer.Verify(self.input, primary_sig))
  
  def __testPublicVerify(self, subdir):
    (verifier, active_sig, primary_sig) = self.__readGoldenOutput(subdir, True)
    self.assertTrue(verifier.Verify(self.input, active_sig))
    self.assertTrue(verifier.Verify(self.input, primary_sig))
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
  
  def testHmacVerify(self):
    self.__testSignerVerify("hmac")
  
  def testBadHmacVerify(self):
    self.__testBadVerify("hmac")
  
  def testDsaSignAndVerify(self):
    self.__testSignAndVerify("dsa")
  
  def testDsaSignerVerify(self):
    self.__testSignerVerify("dsa")
    self.__testPublicVerify("dsa")
  
  def testBadDsaVerify(self):
    self.__testBadVerify("dsa")
  
  def testRsaSignAndVerify(self):
    self.__testSignAndVerify("rsa-sign")
  
  def testRsaSignerVerify(self):
    self.__testSignerVerify("rsa-sign")
    self.__testPublicVerify("rsa-sign")
  
  def testBadRsaVerify(self):
    self.__testBadVerify("rsa-sign")
  
  def testHmacBadSigs(self):
    (signer, sig) = self.__signInput("hmac")
    sig_bytes = util.Decode(sig)
    self.assertRaises(errors.ShortSignatureError, signer.Verify, 
                      self.input, "AB")
    bad_sig = util.Encode(chr(23) + sig_bytes[1:])
    self.assertRaises(errors.BadVersionError, signer.Verify, 
                      self.input, bad_sig)
    bad_sig = util.Encode(sig_bytes[0] + chr(23) + sig_bytes[2:])
    self.assertRaises(errors.BadFormatError, signer.Verify, self.input, bad_sig)
    char = chr(ord(sig_bytes[2]) ^ 45)  # Munge key hash info in sig 
    bad_sig = util.Encode(sig_bytes[:2] + char + sig_bytes[3:])
    self.assertRaises(errors.KeyNotFoundError, signer.Verify, 
                      self.input, bad_sig)
    
  def tearDown(self):
    self.input = None