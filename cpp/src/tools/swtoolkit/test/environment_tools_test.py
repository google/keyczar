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

"""Test for environment_tools.  These are SMALL and MEDIUM tests."""


import os
import unittest
import TestFramework


class EnvToolsTests(unittest.TestCase):
  """Tests for environment_tools module."""

  def setUp(self):
    """Per-test setup."""
    self.env = self.root_env.Clone()

  def testFilterOut(self):
    """Test FilterOut()."""
    env = self.env
    env.Replace(
        TEST1=['ant', 'bear', 'cat'],
        TEST2=[1, 2, 3, 4],
    )

    # Simple filter
    env.FilterOut(TEST1=['bear'])
    self.assertEqual(env['TEST1'], ['ant', 'cat'])

    # Filter multiple
    env.FilterOut(TEST1=['ant'], TEST2=[1, 3])
    self.assertEqual(env['TEST1'], ['cat'])
    self.assertEqual(env['TEST2'], [2, 4])

    # Filter doesn't care if the variable or value doesn't exist
    env.FilterOut(TEST1=['dog'], TEST3=[2])
    self.assertEqual(env['TEST1'], ['cat'])
    self.assertEqual(env['TEST2'], [2, 4])

  def testFilterOutRepeated(self):
    """Test FilterOut() filters all matches."""
    env = self.env
    env['TEST3'] = ['A', 'B', 'B', 'C']
    env.FilterOut(TEST3=['B'])
    self.assertEqual(env['TEST3'], ['A', 'C'])

  def testFilterOutNested(self):
    """Test FilterOut on nested lists."""
    env = self.env
    # FilterOut does not currently flatten lists, nor remove values from
    # sub-lists.  This is related to not evaluating environment variables (see
    # below).
    env['TEST4'] = ['A', ['B', 'C'], 'D']
    env.FilterOut(TEST4=['B'])
    self.assertEqual(env['TEST4'], ['A', ['B', 'C'], 'D'])
    # If you specify the entire sub-list, it will be filtered
    env.FilterOut(TEST4=[['B', 'C']])
    self.assertEqual(env['TEST4'], ['A', 'D'])

  def testFilterOutNoEval(self):
    """Test FilterOut does not evaluate variables in the list."""
    env = self.env
    # FilterOut does not evaluate variables in the list.  (Doing so would
    # defeat much of the purpose of variables.)  Note that this means it does
    # not filter variables which evaluate partially or wholly to the filtered
    # string.  On the plus side, this means you CAN filter out variables.
    env.Replace(
        TEST5=['$V1', '$V2', '$V3', '$V4'],
        V1='A',
        # (V2 intentionally undefined at this point)
        V3=['A', 'B'],
        V4='C',
    )
    env.FilterOut(TEST5=['A', '$V4'])
    self.assertEqual(env['TEST5'], ['$V1', '$V2', '$V3'])

  def testOverlap(self):
    """Test Overlap()."""
    env = self.env
    env.Replace(
        OLVAR='baz',
        OLLIST=['2', '3', '4'],
    )

    # Simple string compares
    self.assertEqual(env.Overlap('foo', 'foo'), ['foo'])
    self.assertEqual(env.Overlap('foo', 'food'), [])

    # String compare with variable substitution
    self.assertEqual(env.Overlap('foobaz', 'foo$OLVAR'), ['foobaz'])

    # Simple list overlap
    # Need to use set() for comparison, since the order of entries in the
    # output list is indeterminate
    self.assertEqual(set(env.Overlap(['1', '2', '3'], ['2', '3', '4'])),
                     set(['2', '3']))

    # Overlap removes duplicates
    self.assertEqual(env.Overlap(['1', '2', '2'], ['2', '3', '2']), ['2'])

    # List and string
    self.assertEqual(env.Overlap('3', ['1', '2', '3']), ['3'])
    self.assertEqual(env.Overlap('4', ['1', '2', '3']), [])
    self.assertEqual(env.Overlap(['1', '$OLVAR', '3'], '$OLVAR'), ['baz'])

    # Variable substitition will replace and flatten lists
    self.assertEqual(set(env.Overlap(['1', '2', '3'], '$OLLIST')),
                     set(['2', '3']))

    # Substitution flattens lists
    self.assertEqual(set(env.Overlap([['1', '2'], '3'], ['2', ['3', '4']])),
                     set(['2', '3']))

  def testSubstList2(self):
    """Test SubstList2()."""
    env = self.env

    # Empty args should return empty list
    self.assertEqual(env.SubstList2(), [])

    # Undefined variable also returns empty list
    self.assertEqual(env.SubstList2('$NO_SUCH_VAR'), [])

    # Simple substitution (recursively evaluates variables)
    env['STR1'] = 'FOO$STR2'
    env['STR2'] = 'BAR'
    self.assertEqual(env.SubstList2('$STR1'), ['FOOBAR'])

    # Simple list substitution
    env['LIST1'] = ['A', 'B']
    self.assertEqual(env.SubstList2('$LIST1'), ['A', 'B'])

    # Nested lists
    env['LIST2'] = ['C', '$LIST1']
    self.assertEqual(env.SubstList2('$LIST2'), ['C', 'A', 'B'])

    # Multiple variables in a single entry stay a single entry
    self.assertEqual(env.SubstList2('$STR1 $STR2'), ['FOOBAR BAR'])

    # Multiple args to command
    self.assertEqual(env.SubstList2('$LIST2', '$STR2'), ['C', 'A', 'B', 'BAR'])

    # Items in list are actually strings, not some subclass
    self.assert_(type(env.SubstList2('$STR1')[0]) is str)

  def testRelativePath(self):
    """Test RelativePath()."""
    env = self.env

    # Trivial cases - directory or file relative to itself
    self.assertEqual(env.RelativePath('a', 'a'), '.')
    self.assertEqual(env.RelativePath('a/b/c', 'a/b/c'), '.')
    self.assertEqual(env.RelativePath('a', 'a', source_is_file=True), 'a')
    self.assertEqual(env.RelativePath('a/b/c', 'a/b/c', source_is_file=True),
                     'c')

    # Can pass in directory or file nodes
    self.assertEqual(env.RelativePath(env.Dir('a'), env.File('b/c'), sep='/'),
                     '../b/c')

    # Separator argument is respected
    self.assertEqual(env.RelativePath('.', 'a/b/c', sep='BOOGA'),
                     'aBOOGAbBOOGAc')

    # Default separator is os.sep
    self.assertEqual(env.RelativePath('.', 'a/b'),
                     'a' + os.sep + 'b')

    # No common dirs
    self.assertEqual(env.RelativePath('a/b/c', 'd/e/f', sep='/'),
                     '../../../d/e/f')
    self.assertEqual(
        env.RelativePath('a/b/c', 'd/e/f', sep='/', source_is_file=True),
        '../../d/e/f')

    # Common dirs
    self.assertEqual(env.RelativePath('a/b/c/d', 'a/b/e/f', sep='/'),
                     '../../e/f')

    # Source or destination path is different length
    self.assertEqual(env.RelativePath('a/b/c/d', 'a/b', sep='/'), '../..')
    self.assertEqual(env.RelativePath('a/b', 'a/b/c/d', sep='/'), 'c/d')

    # Current directory on either side
    self.assertEqual(env.RelativePath('a/b/c', '.', sep='/'), '../../..')
    self.assertEqual(env.RelativePath('.', 'a/b/c', sep='/'), 'a/b/c')

    # Variables are evaluated
    env.Replace(
        DIR1='foo',
        DIR2='bar',
    )
    self.assertEqual(env.RelativePath('foo/$DIR2/a', '$DIR1/bar/b', sep='/'),
                     '../b')

  def testApplyBuildSConscript(self):
    """Test ApplySConscript() and BuildSConscript() (MEDIUM test)."""
    env = self.env
    env['SUB1'] = 'nougat'

    # ApplySConscript() affects the calling environment
    env.ApplySConscript('SConscript1')
    self.assertEqual(env.get('SUB2'), 'orange')

    # BuildSConscript() does not affect the calling environment
    env.BuildSConscript('SConscript2')
    self.assertEqual(env.get('SUB2'), 'orange')

    # BuildSConscript finds build.scons in preference to SConscript
    env.BuildSConscript('abs1')
    # But does look for SConscript if there isn't build.scons
    env.BuildSConscript('abs2')


def TestSConstruct(scons_globals):
  """Test SConstruct file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """

  # Get globals from SCons
  Environment = scons_globals['Environment']

  env = Environment(tools=['environment_tools'])

  # Run unit tests
  TestFramework.RunUnitTests(EnvToolsTests, root_env=env)


sconscript1_contents = """
Import('env')
if env.get('SUB1') != 'nougat':
  raise ValueError('ApplySConscript() failure in sconscript1')
env['SUB2'] = 'orange'
"""

sconscript2_contents = """
Import('env')
if env.get('SUB1') != 'nougat':
  raise ValueError('BuildSConscript() failure in sconscript2')
env['SUB2'] = 'pizza'
"""

sconscript3_contents = """
Import('env')
filename = '%s'
env.Execute(Touch(filename))
"""


def main():
  test = TestFramework.TestFramework()

  test.subdir('environment_tools')
  base = 'environment_tools/'

  test.WriteSConscript(base + 'SConstruct', TestSConstruct)
  test.write(base + 'SConscript1', sconscript1_contents)
  test.write(base + 'SConscript2', sconscript2_contents)
  test.subdir(base + 'abs1')
  test.write(base + 'abs1/build.scons', sconscript3_contents % 'yes1')
  test.write(base + 'abs1/SConscript', sconscript3_contents % 'no')
  test.subdir(base + 'abs2')
  test.write(base + 'abs2/SConscript', sconscript3_contents % 'yes2')

  # Ignore stderr since unittest prints its output there
  test.run(chdir=base, stderr=None)
  test.must_exist(base + 'abs1/yes1')
  test.must_not_exist(base + 'abs1/no')
  test.must_exist(base + 'abs2/yes2')
  test.pass_test()

if __name__ == '__main__':
  main()
