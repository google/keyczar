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

"""Component builders publishing test (SMALL test)."""

import sys
import unittest
import TestFramework


class ComponentBuilderPublishTests(unittest.TestCase):
  """Tests for component_builders module publishing resources."""

  def assertPublished(self, target, resource_type, files):
    """Check that the target has published the specified files.

    Args:
      target: Name of target.
      resource_type: Type of resource.
      files: List of files expected to be published.  SCons variables will be
          evaluated before comparison.

    Raises:
      AssertionError: Published files do not match expected list.
    """
    env = self.env

    # Get sorted list of published files
    found = sorted(map(str, env.GetPublished(target, resource_type)))

    # Get list of expected files
    expected = sorted(str(env.File(x)) for x in files)

    if found != expected:
      raise AssertionError('Target %r resource %r expected %r, found %r' %
                           (target, resource_type, expected, found))

  def testPublished(self):
    """Test that the correct artifacts were published."""

    # Static library
    self.assertPublished(
        'a_static_lib', 'link',
        ['$OBJ_ROOT/${LIBPREFIX}a_static_lib$LIBSUFFIX'])
    self.assertPublished('a_static_lib', 'run', [])
    self.assertPublished('a_static_lib', 'debug', [])

    # Shared library
    self.assertPublished(
        'a_shared_lib', 'run',
        ['$OBJ_ROOT/${SHLIBPREFIX}a_shared_lib$SHLIBSUFFIX'])
    if sys.platform in ('win32', 'cygwin'):
      # Link against .lib, debug info in .pdb
      self.assertPublished(
          'a_shared_lib', 'link',
          ['$OBJ_ROOT/${LIBPREFIX}a_shared_lib$LIBSUFFIX'])
      self.assertPublished(
          'a_shared_lib', 'debug',
          ['$OBJ_ROOT/${SHLIBPREFIX}a_shared_lib.pdb'])
    else:
      # Posix - link against .so/.dylib, debug info in the shared lib itself.
      self.assertPublished(
          'a_shared_lib', 'link',
          ['$OBJ_ROOT/${SHLIBPREFIX}a_shared_lib$SHLIBSUFFIX'])
      self.assertPublished('a_shared_lib', 'debug', [])

    # Program
    self.assertPublished('a_prog', 'run', ['$OBJ_ROOT/a_prog$PROGSUFFIX'])
    if sys.platform in ('win32', 'cygwin'):
      self.assertPublished('a_prog', 'debug', ['$OBJ_ROOT/a_prog.pdb'])
    else:
      self.assertPublished('a_prog', 'debug', [])

    # Test program
    self.assertPublished('a_test', 'run', ['$OBJ_ROOT/a_test$PROGSUFFIX'])
    if sys.platform in ('win32', 'cygwin'):
      self.assertPublished('a_test', 'debug', ['$OBJ_ROOT/a_test.pdb'])
    else:
      self.assertPublished('a_test', 'debug', [])


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

  # Exit normally, before SCons tries to build anything
  sys.exit(0)


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
  env.ComponentLibrary('a_static_lib', a_obj, COMPONENT_STATIC=True)
  env.ComponentLibrary('a_shared_lib', a_obj, COMPONENT_STATIC=False)
  env.ComponentProgram('a_prog', a_obj)
  env.ComponentTestProgram('a_test', a_obj)

  # Run unit tests inside the SConscript, since they're platform-specific
  TestFramework.RunUnitTests(ComponentBuilderPublishTests, env=env.Clone())

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

  base = 'test/'
  test.subdir(base)
  test.WriteSConscript(base + 'SConstruct', TestSConstruct)
  test.WriteSConscript(base + 'SConscript', TestSConscript)
  test.write(base + 'a.cpp', a_cpp_contents)

  test.run(chdir=base, stderr=None)
  test.pass_test()

if __name__ == '__main__':
  main()
