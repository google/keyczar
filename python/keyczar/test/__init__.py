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
Tests for Keyczar Cryptography Toolkit

Suite of unit tests for keyczar package.

@author: arkajit.dey@gmail.com (Arkajit Dey)
"""
from __future__ import absolute_import

import unittest

from . import crypter_test
from . import keyczart_test
from . import signer_test
from . import util_test
from . import session_test
from . import interop_test
from . import collision_test

def allsuite():
  alltests = unittest.TestSuite()
  alltests.addTest(crypter_test.suite())
  alltests.addTest(keyczart_test.suite())
  alltests.addTest(signer_test.suite())
  alltests.addTest(util_test.suite())
  alltests.addTest(session_test.suite())
  alltests.addTest(interop_test.suite())
  alltests.addTest(collision_test.suite())
  return alltests