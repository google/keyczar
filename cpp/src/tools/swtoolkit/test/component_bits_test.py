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

"""Test for component_bits.  These are SMALL tests."""

import sys
import unittest
import TestFramework


class BitTests(unittest.TestCase):
  """Tests for component_bits module."""

  def setUp(self):
    """Per-test setup."""
    self.env = self.root_env.Clone()

  def testDeclareBit(self):
    """Test DeclareBit()."""

    DeclareBit('apple', 'Fruity bit')

    # Redeclaring with the same definition is ok
    DeclareBit('apple', 'Fruity bit')

    # Redeclaring with a different definition should raise an exception
    self.assertRaises(ValueError, DeclareBit, 'apple', 'Vegetable')

    # Must specify a definition
    self.assertRaises(TypeError, DeclareBit, 'pear')

  def testBit(self):
    """Test Bit()."""
    env = self.env

    # Bits are not set by default
    DeclareBit('berry', 'Fruit from vine')
    self.assert_(not env.Bit('berry'))

    # Undeclared bits raise exceptions
    self.assertRaises(ValueError, env.Bit, 'cherry')

    # Check set and clear bits
    env.SetBits('berry')
    self.assert_(env.Bit('berry'))
    env.ClearBits('berry')
    self.assert_(not env.Bit('berry'))

  def testSetBits(self):
    """Test SetBits()."""
    env = self.env

    DeclareBit('sb1', 'Set bit 1 test')
    DeclareBit('sb2', 'Set bit 2 test', exclusive_groups=['harvard', 'yale'])
    DeclareBit('sb3', 'Set bit 3 test', exclusive_groups='harvard')
    DeclareBit('sb4', 'Set bit 4 test', exclusive_groups='yale')
    DeclareBit('sb5', 'Set bit 5 test')
    DeclareBit('sb6', 'Set bit 6 test')

    # Undeclared bit anywhere in the list should raise exception
    self.assertRaises(ValueError, env.SetBits, 'sb1', 'sb2', 'sb99')

    # Set a single bit
    self.assert_(not env.Bit('sb3'))
    env.SetBits('sb3')      # One harvard bit only
    self.assert_(env.Bit('sb3'))

    # Set multiple bits
    self.assert_(not env.Bit('sb5'))
    self.assert_(not env.Bit('sb6'))
    env.SetBits('sb5', 'sb6')
    self.assert_(env.Bit('sb5'))
    self.assert_(env.Bit('sb6'))

    # Check exclusive groups support
    env.SetBits('sb3')      # Ok to set the same bit again
    env.SetBits('sb1')      # Didn't go to harvard; that's ok
    # One harvard grad only
    self.assertRaises(ValueError, env.SetBits, 'sb2')
    # Get rid of the first harvard bit; should be able to set the second
    env.ClearBits('sb3')
    env.SetBits('sb2')
    # The yale exclusive bit should prevent sb4 from being set
    self.assertRaises(ValueError, env.SetBits, 'sb4')
    # Set multiple bits should check exceptions on all bits
    self.assertRaises(ValueError, env.SetBits, 'sb5', 'sb4')

  def testClearBits(self):
    """Test ClearBits()."""
    env = self.env

    DeclareBit('cb1', 'Clear bit 1')
    DeclareBit('cb2', 'Clear bit 2')
    DeclareBit('cb3', 'Clear bit 3')

    env.SetBits('cb1', 'cb2', 'cb3')
    env.ClearBits('cb1')
    self.assert_(not env.Bit('cb1'))
    self.assert_(env.Bit('cb2'))
    env.ClearBits('cb2', 'cb3')
    self.assert_(not env.Bit('cb2'))
    self.assert_(not env.Bit('cb3'))

    # Undeclared bit anywhere in the list should raise exception
    self.assertRaises(ValueError, env.ClearBits, 'cb1', 'cb42', 'cb2')

  def testAnyAllBits(self):
    """Test AnyBits() and AllBits()."""
    env = self.env

    DeclareBit('true1', 'Any/allbits true 1')
    DeclareBit('true2', 'Any/allbits true 2')
    DeclareBit('false1', 'Any/allbits false 1')
    DeclareBit('false2', 'Any/allbits false 2')
    env.SetBits('true1', 'true2')

    self.assert_(env.AnyBits('true1'))
    self.assert_(not env.AnyBits('false1'))
    self.assert_(env.AnyBits('false1', 'true1', 'false2'))
    self.assert_(not env.AnyBits('false1', 'false2'))

    self.assert_(env.AllBits('true1'))
    self.assert_(not env.AllBits('false1'))
    self.assert_(not env.AllBits('true1', 'false1', 'true2'))
    self.assert_(env.AllBits('true1', 'true2'))

    # Undeclared bit anywhere in the list should raise exception
    self.assertRaises(ValueError, env.AnyBits, 'true1', 'ambivalent')
    self.assertRaises(ValueError, env.AllBits, 'eggplant', 'true1')

  def testSetBitFromOption(self):
    """Test SetBitFromOption()."""
    env = self.env

    DeclareBit('opt1', 'option 1')
    DeclareBit('opt2', 'option 2')
    DeclareBit('opt3', 'option 3')
    DeclareBit('opt4', 'option 4')

    # If arg not specified, default should be used
    env.SetBits('opt1')
    env.SetBitFromOption('opt1', False)
    self.assert_(not env.Bit('opt1'))

    env.SetBitFromOption('opt2', True)
    self.assert_(env.Bit('opt2'))

    # Ok to set bit from option twice.  This lets us use SetBitFromOption() in
    # a SConscript which is invoked in multiple sub-environments.
    env.ClearBits('opt2')
    env.SetBitFromOption('opt2', True)
    self.assert_(env.Bit('opt2'))

    # Set via option, default=false
    env.SetBitFromOption('opt3', False)
    self.assert_(env.Bit('opt3'))

    env.SetBits('opt4')
    env.SetBitFromOption('opt4', True)
    self.assert_(not env.Bit('opt4'))

    # Undeclared bit should raise exception
    self.assertRaises(ValueError, env.SetBitFromOption, 'opt99', False)

  def testPredeclaredBits(self):
    """Test predeclared bits."""
    env = self.env

    # None of the target bits should be set yet, but they should be declared.
    # The AnyBits() call will throw an exception if they're not.
    self.assert_(not env.AnyBits('debug', 'mac', 'linux', 'posix', 'windows'))

    # Check that the correct host bit is set
    if sys.platform in ('win32', 'cygwin'):
      self.assert_(env.Bit('host_windows'))
      self.assert_(not env.AnyBits('host_mac', 'host_linux'))
    elif sys.platform in ('linux', 'linux2'):
      self.assert_(env.Bit('host_linux'))
      self.assert_(not env.AnyBits('host_mac', 'host_windows'))
    elif sys.platform == 'darwin':
      self.assert_(env.Bit('host_mac'))
      self.assert_(not env.AnyBits('host_linux', 'host_windows'))


def TestSConstruct(scons_globals):
  """Test SConstruct file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """

  # Get globals from SCons
  Environment = scons_globals['Environment']

  env = Environment(tools=['component_setup', 'component_bits'])

  # Run unit tests
  TestFramework.RunUnitTests(BitTests, root_env=env)


def main():
  base = 'component_bits'
  test = TestFramework.TestFramework()
  test.subdir(base)
  test.WriteSConscript(base + '/SConstruct', TestSConstruct)
  # Need to ignore stderr, since that's where unittest prints its output
  test.run(chdir=base, options='--opt3 --no-opt4', stderr=None)
  test.pass_test()


if __name__ == '__main__':
  main()
