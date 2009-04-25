#!/usr/bin/python2.4
# Copyright 2009, Google Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following disclaimer
# in the documentation and/or other materials provided with the
# distribution.
#     * Neither the name of Google Inc. nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Test for distcc.  These are SMALL tests."""


import sys
import unittest
import TestFramework


class DistccTestBase(unittest.TestCase):
  """Base class for distcc tests."""

  def setUp(self):
    """Per-test setup."""
    self.env = self.root_env.Clone()

    # Hook env.Detect(); defaults to distcc present
    self.old_detect = self.env.Detect
    self.env.Detect = self.MockDetect
    self.mock_detect_return = 1

    # Hook env.WhereIs(), so we get a consistent path for cc, c++
    self.old_whereis = self.env.WhereIs
    self.env.WhereIs = self.MockWhereIs

    # Set up default values for CC, CXX, HOME, DISTCC_HOSTS
    self.env.Replace(
        CC='cc',
        CXX='c++',
        DISTCC_HOSTS='foo,bar',
        HOME='home',
    )

  def MockDetect(self, filename):
    """Mock of env.Detect().

    Args:
      filename: Program file to detect.

    Returns:
      Mock value for 'distcc', else passthrough to env.Detect().
    """
    if filename == 'distcc':
      return self.mock_detect_return
    else:
      return self.old_detect(filename)

  def MockWhereIs(self, filename):
    """Mock of env.WhereIs().

    Args:
      filename: Program file to convert to full path.

    Returns:
      Mock value for 'cc' and 'c++', else passthrough to env.WhereIs().
    """
    if filename in ('cc', 'c++'):
      return '/simulated/' + filename
    else:
      return self.old_whereis(filename)


class DistccTestNoOption(DistccTestBase):
  """Tests for distcc module when --distcc not specified on command line."""

  def testOptionClear(self):
    """Test --distcc option not on command line."""
    env = self.env

    # IF distcc option is not set, do nothing
    env.Tool('distcc')
    self.assertEqual(env['CC'], 'cc')
    self.assertEqual(env['CXX'], 'c++')


class DistccTests(DistccTestBase):
  """Tests for distcc module when --distcc is specified."""

  def testNotPresent(self):
    """Test distcc not present."""
    env = self.env

    # If distcc is not detected on the system, CC and CXX are not modified
    self.mock_detect_return = 0
    env.Tool('distcc')
    self.assertEqual(env['CC'], 'cc')
    self.assertEqual(env['CXX'], 'c++')

  def testHOMENotSet(self):
    """Test $HOME not set."""
    env = self.env

    # IF $HOME is not set, do nothing
    env['HOME'] = None
    env.Tool('distcc')
    self.assertEqual(env['CC'], 'cc')
    self.assertEqual(env['CXX'], 'c++')

  def testHOSTSNotSet(self):
    """Test $DISTCC_HOSTS not set."""
    env = self.env

    # IF $DISTCC_HOSTS is not set, do nothing
    env['DISTCC_HOSTS'] = None
    env.Tool('distcc')
    self.assertEqual(env['CC'], 'cc')
    self.assertEqual(env['CXX'], 'c++')

  def testUnknownCompilers(self):
    """Test not modifying unknown compilers."""
    env = self.env

    # If C/C++ compilers are not in the known list, shouldn't modify them
    env.Replace(CC='someothercc', CXX='someothercxx')
    env.Tool('distcc')
    self.assertEqual(env['CC'], 'someothercc')
    self.assertEqual(env['CXX'], 'someothercxx')

  def testNormal(self):
    """Test normal invocation; compiler commands should be modified."""
    env = self.env

    env.Tool('distcc')

    if sys.platform == 'darwin':
      # Full path on darwin
      self.assertEqual(env['CC'], '$DISTCC /simulated/cc')
      self.assertEqual(env['CXX'], '$DISTCC /simulated/c++')
    else:
      # Relative path elsewhere
      self.assertEqual(env['CC'], '$DISTCC cc')
      self.assertEqual(env['CXX'], '$DISTCC c++')


def TestSConstruct(scons_globals):
  """Test SConstruct file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """

  # Get globals from SCons
  Environment = scons_globals['Environment']

  env = Environment(tools=['component_setup'])

  # Run unit tests
  TestFramework.RunUnitTests(DistccTests, root_env=env)


def TestSConstructNoOption(scons_globals):
  """Test SConstruct file for default behavior when --distcc not specified.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """

  # Get globals from SCons
  Environment = scons_globals['Environment']

  env = Environment(tools=['component_setup'])

  # Run unit tests
  TestFramework.RunUnitTests(DistccTestNoOption, root_env=env)


def main():
  test = TestFramework.TestFramework()

  # Run tests where --distcc is not specified
  base = 'distcc_off/'
  test.subdir(base)
  test.WriteSConscript(base + 'SConstruct', TestSConstructNoOption)
  # Ignore stderr since unittest prints its output there
  test.run(chdir=base, stderr=None)

  # Run tests where --distcc is specified
  base = 'distcc/'
  test.subdir(base)
  test.WriteSConscript(base + 'SConstruct', TestSConstruct)
  test.run(chdir=base, stderr=None, options='--distcc')

  test.pass_test()

if __name__ == '__main__':
  main()
