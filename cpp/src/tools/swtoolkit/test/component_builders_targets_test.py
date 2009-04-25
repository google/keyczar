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

"""Component builders targets test (SMALL test)."""

import os
import sys
import unittest
import TestFramework


class ComponentBuilderTargetsTests(unittest.TestCase):
  """Tests for defer module."""

  def assertTargetsInGroup(self, group_name, expected):
    """Check that the group contains only the expected targets.

    Args:
      group_name: Name of group.
      expected: List of expected targets in the group.  Order does not matter.

    Raises:
      AssertionError: List does not match.
    """
    groups = GetTargetGroups()
    if group_name not in groups:
      raise AssertionError('Group %r does not exist' % group_name)

    # Copy targets and expected so we can sort them
    targets = groups[group_name].GetTargetNames()[:]
    expected = expected[:]

    # Sort and compare
    targets.sort()
    expected.sort()
    if targets != expected:
      raise AssertionError('Group %r expected %r, found %r' %
                           (group_name, expected, targets))

  def testDefaultGroups(self):
    """Test target assignment to default groups."""
    self.assertTargetsInGroup('all_libraries', [
        'a_lib',
        'b_lib',
    ])
    self.assertTargetsInGroup('all_programs', [
        'a_prog',
        'b_prog',
    ])
    self.assertTargetsInGroup('all_packages', [
        'a_package',
        'b_package',
    ])
    self.assertTargetsInGroup('all_test_programs', [
        'a_test',
        'b_test',
        'b_disabled_test',
        'disabled_test',
        'l_test',
        'm_test',
        's_test',
        'unsized_test',
    ])

  def testRunGroups(self):
    """Test target assignment to groups for running tests."""
    self.assertTargetsInGroup('run_all_tests', [
        'a_out',
        'b_out',
        'run_a_test',
        'run_b_test',
        'run_l_test',
        'run_m_test',
        'run_s_test',
        'run_unsized_test',
    ])
    self.assertTargetsInGroup('run_large_tests', [
        'a_out',
        'b_out',
        'c_out',
        'run_a_test',
        'run_b_test',
        'run_c_test',
        'run_l_test',
    ])
    self.assertTargetsInGroup('run_medium_tests', [
        'run_m_test',
    ])
    self.assertTargetsInGroup('run_small_tests', [
        'run_s_test',
    ])
    self.assertTargetsInGroup('run_disabled_tests', [
        'run_disabled_test',
        'run_b_disabled_test',
        'run_c_disabled_test',
    ])

  def testUserAddedGroups(self):
    """Test target assignment to user-added groups."""
    self.assertTargetsInGroup('new_lib_group', [
        'b_lib',
        'c_lib',
    ])
    self.assertTargetsInGroup('new_prog_group', [
        'b_prog',
        'c_prog',
    ])
    self.assertTargetsInGroup('new_package_group', [
        'b_package',
        'c_package',
    ])
    self.assertTargetsInGroup('new_test_group', [
        'b_test',
        'b_disabled_test',
        'c_test',
        'c_disabled_test',
    ])
    self.assertTargetsInGroup('new_test_out_group', [
        'b_out',
        'c_out',
        'run_b_test',
        'run_c_test',
    ])

#------------------------------------------------------------------------------


def TestSConstruct(scons_globals):
  """Test SConstruct file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """

  # Get globals from SCons
  Environment = scons_globals['Environment']

  base_env = Environment(tools=['component_setup'])
  base_env.Append(BUILD_COMPONENTS=['SConscript'])

  windows_env = base_env.Clone(
      tools=['target_platform_windows'],
      BUILD_TYPE='dbg',
      BUILD_TYPE_DESCRIPTION='Debug Windows build',
  )
  windows_env.Append(BUILD_GROUPS=['default'])

  mac_env = base_env.Clone(
      tools=['target_platform_mac'],
      BUILD_TYPE='dbg',
      BUILD_TYPE_DESCRIPTION='Debug Mac build',
  )
  mac_env.Append(BUILD_GROUPS=['default'])

  linux_env = base_env.Clone(
      tools=['target_platform_linux'],
      BUILD_TYPE='dbg',
      BUILD_TYPE_DESCRIPTION='Debug Linux build',
  )
  linux_env.Append(BUILD_GROUPS=['default'])

  BuildComponents([windows_env, mac_env, linux_env])

  # Run unit tests
  TestFramework.RunUnitTests(ComponentBuilderTargetsTests)


def TestSConscript(scons_globals):
  """Test SConscript file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """
  # Get globals from SCons
  scons_globals['Import']('env')
  env = scons_globals['env']

  # Build an object so we can link it into different targets
  a_obj = env.ComponentObject('a.cpp')

  # Targets with default settings
  env.ComponentLibrary('a_lib', a_obj)
  env.ComponentProgram('a_prog', a_obj)
  env.ComponentPackage('a_package', 'a_package_dir')
  env.ComponentTestOutput('a_out', ['a_out.txt'])

  # Test program goes in the all_tests group, and by default goes in large
  # tests.  Also should create run_a_test.
  env.ComponentTestProgram('a_test', a_obj)

  # Check explicit test size
  env.ComponentTestProgram('s_test', a_obj, COMPONENT_TEST_SIZE='small')
  env.ComponentTestProgram('m_test', a_obj, COMPONENT_TEST_SIZE='medium')
  env.ComponentTestProgram('l_test', a_obj, COMPONENT_TEST_SIZE='large')
  env.ComponentTestProgram('unsized_test', a_obj, COMPONENT_TEST_SIZE=None)

  # Disabled test programs are only run by the disabled test programs group
  env.ComponentTestProgram('disabled_test', a_obj,
                           COMPONENT_TEST_ENABLED=False)

  # Add explicit groups for a second set of targets.
  AddTargetGroup('new_lib_group', 'new libs can be built')
  AddTargetGroup('new_prog_group', 'new programs can be built')
  AddTargetGroup('new_package_group', 'new packages can be built')
  AddTargetGroup('new_test_group', 'new tests can be built')
  AddTargetGroup('new_test_out_group', 'new tests can be run')

  env.Append(
      COMPONENT_LIBRARY_GROUPS=['new_lib_group'],
      COMPONENT_PACKAGE_GROUPS=['new_package_group'],
      COMPONENT_PROGRAM_GROUPS=['new_prog_group'],
      COMPONENT_TEST_PROGRAM_GROUPS=['new_test_group'],
      COMPONENT_TEST_OUTPUT_GROUPS=['new_test_out_group'],
  )
  env.ComponentLibrary('b_lib', a_obj)
  env.ComponentProgram('b_prog', a_obj)
  env.ComponentPackage('b_package', 'b_package_dir')
  env.ComponentTestOutput('b_out', ['b_out.txt'])
  env.ComponentTestProgram('b_test', a_obj)
  env.ComponentTestProgram('b_disabled_test', a_obj,
                           COMPONENT_TEST_ENABLED=False)

  # Explicitly set target groups for a third set of targets.
  env.Replace(
      COMPONENT_LIBRARY_GROUPS=['new_lib_group'],
      COMPONENT_PACKAGE_GROUPS=['new_package_group'],
      COMPONENT_PROGRAM_GROUPS=['new_prog_group'],
      COMPONENT_TEST_PROGRAM_GROUPS=['new_test_group'],
      COMPONENT_TEST_OUTPUT_GROUPS=['new_test_out_group'],
  )
  env.ComponentLibrary('c_lib', a_obj)
  env.ComponentProgram('c_prog', a_obj)
  env.ComponentPackage('c_package', 'c_package_dir')
  env.ComponentTestOutput('c_out', ['c_out.txt'])
  env.ComponentTestProgram('c_test', a_obj)
  env.ComponentTestProgram('c_disabled_test', a_obj,
                           COMPONENT_TEST_ENABLED=False)


#------------------------------------------------------------------------------


abc_h_contents = """
void testa();
void testb();

#ifndef OS_WINDOWS
#define MYEXPORT
#elif defined(C_CPP_EXPORT)
#define MYEXPORT __declspec(dllexport)
#else
#define MYEXPORT __declspec(dllimport)
#endif

void MYEXPORT testc();
"""

a_cpp_contents = """
#include <stdio.h>

void testa() {
  printf("TestA\\n");
}
"""


def main():
  test = TestFramework.TestFramework()

  # TODO: get this to work on windows and linux under coverage.
  if (os.environ.get('COVERAGE_HOOK') and
      sys.platform in ['win32', 'cygwin', 'linux', 'linux2', 'posix']):
    msg = 'Platform %s cannot run this test during coverage currently.\n'
    test.skip_test(msg % repr(sys.platform))
    return

  test.subdir('test')

  base = 'test/'

  test.WriteSConscript(base + 'SConstruct', TestSConstruct)
  test.WriteSConscript(base + 'SConscript', TestSConscript)
  test.write(base + 'a.cpp', a_cpp_contents)

  test.run(chdir=base, options='-h', stderr=None)
  test.pass_test()

if __name__ == '__main__':
  main()
