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

"""Test for defer.  These are SMALL tests."""

import unittest
import SCons.Errors
import TestFramework

#------------------------------------------------------------------------------


class DeferTests(unittest.TestCase):
  """Tests for defer module."""

  def setUp(self):
    """Per-test setup."""
    self.call_list = []
    self.env = self.root_env.Clone()

  def testSimpleDefer(self):
    """Simple defer, passing function pointers."""

    def Sub1(env):
      self.call_list.append(1)
      # Somewhat counter-intuitively, defer does NOT make a copy of the
      # environment, so VAR1 will actually be 'cherry' here.  Should we change
      # this?
      self.assertEqual(env['VAR1'], 'cherry')

    def Sub2(env):
      env = env
      self.call_list.append(2)

    def Sub3(env):
      env = env
      self.call_list.append(3)

    env = self.env
    env['VAR1'] = 'apple'
    env.Defer(Sub1)
    env['VAR1'] = 'cherry'
    env.Defer(Sub2, after=Sub1)
    env.Defer(Sub3)

    # Now add relationships between Sub3 and other methods.  Note that while
    # after can refer to a function directly or by name, the function we're
    # deferring needs to be referenced by name, since otherwise it'll add
    # another instance that function to the list.
    env.Defer('Sub3', after=Sub1)
    env.Defer('Sub2', after='Sub3')

    # Functions are not called until ExecuteDefer()
    self.assertEqual(self.call_list, [])
    env.ExecuteDefer()
    self.assertEqual(self.call_list, [1, 3, 2])

    # Calling ExecuteDefer() again won't do anything, since the previous call
    # consumed the deferred functions.
    env.ExecuteDefer()
    self.assertEqual(self.call_list, [1, 3, 2])

  def testDeferGroups(self):
    """Test defer groups."""

    def Sub1a(env):
      env = env
      self.call_list.append(1)

    def Sub1b(env):
      env = env
      # Append the same thing as 4a; order within defer groups is not defined.
      self.call_list.append(1)

    def Sub2(env):
      env = env
      self.call_list.append(2)

    def Sub3(env):
      env = env
      self.call_list.append(3)

    def Sub4(env):
      env = env
      self.call_list.append(4)

    def Sub5(env):
      env = env
      self.call_list.append(5)

    def Sub6(env):
      env = env
      self.call_list.append(6)

    env = self.env
    # Note that we can set up the relationships by name before any functions
    # are actually deferred.  Also note that each function is implicitly in a
    # group with its function name.
    env.Defer('GroupA', after='Sub4')
    # Can defer after multiple groups/functions, by either name or reference.
    # Note that Sub6 is not actually deferred; just passing it in after, or by
    # name only, doesn't cause it to be called.
    env.Defer('Sub6')
    env.Defer('GroupB', after=['GroupC', Sub5, Sub6])
    env.Defer(Sub1a, 'GroupC', after='GroupA')
    env.Defer(Sub1b, 'GroupC')
    env.Defer(Sub2, 'GroupA')
    env.Defer(Sub3, 'GroupB')
    env.Defer(Sub4)
    env.Defer(Sub5)

    env.ExecuteDefer()
    self.assertEqual(self.call_list, [4, 5, 2, 1, 1, 3])

  def testDeferNotString(self):
    """Test attempts to defer after things that aren't strings or functions."""
    env = self.env

    # Can only defer after strings and functions
    self.assertRaises(ValueError, env.Defer, 'GroupB', after=42)

  def testDeferInheritance(self):
    """Test defer inheritance."""

    def Sub1(env):
      env = env
      self.call_list.append(1)

    def Sub2(env):
      env = env
      self.call_list.append(2)

    def Sub3(env):
      env = env
      self.call_list.append(3)

    env = self.env
    env.Defer(Sub1)
    # Permitted (but not required) to forward-declare defer-after relationships
    env.Defer('GroupA', after=Sub1)

    env_child1 = env.Clone()
    env_child1.Defer('GroupA', Sub2)
    env_child2 = env.Clone()
    env_child2.Defer('GroupA', Sub3)

    env.ExecuteDefer()              # Should execute Sub1 but not Sub2
    self.assertEqual(self.call_list, [1])

    self.call_list = []
    env_child1.ExecuteDefer()       # Should execute Sub1 (again) and Sub2
    self.assertEqual(self.call_list, [1, 2])

    self.call_list = []
    env_child2.ExecuteDefer()       # Should execute Sub1 (again) and Sub3
    self.assertEqual(self.call_list, [1, 3])

  def testDeferRoot(self):
    """Test defer root."""

    # If SetDeferRoot() is used, deferrals are executed by the root's
    # ExecuteDefer().  Deferrals inherited from parent environments are brought
    # down to the new root environment.  Subsequent deferrals from children of
    # the root keep their environments as specified by Defer().
    def Sub1(env):
      self.call_list.append(1)
      # Defer from child of root is passed the child environment
      self.assertEqual(env['VAR1'], 'child')

    def Sub2(env):
      self.call_list.append(2)
      # Defer from parent of root is passed the root environment
      self.assertEqual(env['VAR2'], 'defer_root')

    env_parent = self.env.Clone(VAR2='parent')
    env_parent.Defer(Sub2)
    env_defer_root = env_parent.Clone(VAR2='defer_root')
    env_defer_root.SetDeferRoot()
    env_child = env_defer_root.Clone(VAR1='child')
    env_child.Defer(Sub1, after=Sub2)

    # Since child is now the root, calling ExecuteDefer() from one of its
    # children does nothing.
    env_child.ExecuteDefer()
    self.assertEqual(self.call_list, [])

    env_defer_root.ExecuteDefer()       # Should run Sub1
    self.assertEqual(self.call_list, [2, 1])

    # Environments above the one calling GetDeferRoot() keep their own roots.
    self.assertEqual(env_parent.GetDeferRoot(), env_parent)
    # Environments at or beneath should see the context for GetDeferRoot().
    self.assertEqual(env_defer_root.GetDeferRoot(), env_defer_root)
    self.assertEqual(env_child.GetDeferRoot(), env_defer_root)

  def testDeferReentrancy(self):
    """Test re-entrant calls to ExecuteDefer()."""

    def Sub1(env):
      env.ExecuteDefer()

    env = self.env
    env.Defer(Sub1)
    self.assertRaises(SCons.Errors.UserError, env.ExecuteDefer)

  def testDeferNested(self):
    """Test nested calls to ExecuteDefer()."""

    def Sub1(env):
      env = env
      self.call_list.append(1)

    def Sub2(env):
      env = env
      self.call_list.append(2)
      env.Defer(Sub1)

    def Sub3(env):
      env = env
      self.call_list.append(3)

    env = self.env
    env.Defer(Sub2)
    env.Defer(Sub3, after=Sub2)

    # Make sure PrintDefer() at least doesn't crash.
    env.PrintDefer()

    env.ExecuteDefer()
    self.assertEqual(self.call_list, [2, 1, 3])


#------------------------------------------------------------------------------


def TestSConstruct(scons_globals):
  """Test SConstruct file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """

  # Get globals from SCons
  Environment = scons_globals['Environment']
  env = Environment(tools=['environment_tools', 'defer'])

  # Run unit tests
  TestFramework.RunUnitTests(DeferTests, root_env=env)


def main():
  test = TestFramework.TestFramework()
  test.subdir('defer')
  base = 'defer/'
  test.WriteSConscript(base + 'SConstruct', TestSConstruct)
  test.run(chdir=base, stderr=None)
  test.pass_test()


if __name__ == '__main__':
  main()
