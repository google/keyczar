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
Suite of all unittests for Python Keyczar.

@author: arkajit.dey@gmail.com (Arkajit Dey)
"""

import unittest

import crypter_test
import keyczart_test
import signer_test
import util_test
import session_test

def suite():
  alltests = unittest.TestSuite()
  alltests.addTest(crypter_test.suite())
  alltests.addTest(keyczart_test.suite())
  alltests.addTest(signer_test.suite())
  alltests.addTest(util_test.suite())
  alltests.addTest(session_test.suite())
  return alltests

if __name__ == '__main__':
  unittest.main(defaultTest='suite')
