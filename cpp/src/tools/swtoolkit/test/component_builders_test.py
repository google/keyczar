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

"""Component builders test for software construction tookit (LARGE test)."""

import TestFramework
import os
import sys


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


def TestSConscript(scons_globals):
  """Test SConscript file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """
  # Get globals from SCons
  scons_globals['Import']('env')
  env = scons_globals['env']

  # Build an object
  a_obj = env.ComponentObject('a.cpp')

  # Build a static library
  env.ComponentLibrary('b', 'b.cpp', COMPONENT_STATIC=True)

  # Build a shared library
  env.ComponentLibrary('g', 'g.cpp', COMPONENT_STATIC=False)

  # Build a program
  env.Append(LIBS=['b', 'g'])
  env.ComponentProgram('d', ['d.cpp', a_obj])

  # Build a test program
  env.ComponentTestProgram('e', ['e.cpp', a_obj])


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
#include "abc.h"

void testa() {
  printf("TestA\\n");
}
"""

b_cpp_contents = """
#include <stdio.h>
#include "abc.h"

void testb() {
  printf("TestB\\n");
}
"""

g_cpp_contents = """
#include <stdio.h>

#define C_CPP_EXPORT
#include "abc.h"

void MYEXPORT testc() {
  printf("TestC\\n");
}
"""

d_cpp_contents = """
#include <stdio.h>
#include "abc.h"

int main(void) {
  printf("TestD\\n");
  testa();
  testb();
  testc();
  return 0;
}
"""

e_cpp_contents = """
#include <stdio.h>
#include "abc.h"

int main(void) {
  printf("TestE\\n");
  testa();
  testb();
  testc();
  return 0;
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
  test.write(base + 'abc.h', abc_h_contents)
  test.write(base + 'a.cpp', a_cpp_contents)
  test.write(base + 'b.cpp', b_cpp_contents)
  test.write(base + 'g.cpp', g_cpp_contents)
  test.write(base + 'd.cpp', d_cpp_contents)
  test.write(base + 'e.cpp', e_cpp_contents)

  test.run(chdir=base, options='d')
  test.must_exist(base + 'scons-out/dbg/staging/d' + TestFramework.exe_suffix)
  test.must_exist(base + 'scons-out/dbg/staging/%sg%s' % (
      TestFramework.dll_prefix, TestFramework.dll_suffix))
  test.run(program=test.workpath(base + 'scons-out/dbg/staging/d' +
                                 TestFramework.exe_suffix),
           stdout='TestD\nTestA\nTestB\nTestC\n')

  test.run(chdir=base, options='run_all_tests')
  test.must_exist(base + 'scons-out/dbg/tests/e' + TestFramework.exe_suffix)
  test.must_exist(base + 'scons-out/dbg/tests/%sg%s' % (
      TestFramework.dll_prefix, TestFramework.dll_suffix))
  test.must_match(base + 'scons-out/dbg/test_output/e.out.txt',
                  'TestE\nTestA\nTestB\nTestC\n')

  test.pass_test()

if __name__ == '__main__':
  main()
