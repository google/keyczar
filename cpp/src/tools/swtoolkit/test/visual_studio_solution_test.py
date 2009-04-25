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

"""Visual studio solution test (MEDIUM test)."""

import sys
import TestFramework


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
      tools=['target_platform_windows', 'visual_studio_solution'],
      BUILD_TYPE='dbg',
      BUILD_TYPE_DESCRIPTION='Debug Windows build',
  )
  windows_env.Append(BUILD_GROUPS=['default'])

  BuildComponents([windows_env])

  # Solution and target projects
  s = windows_env.Solution('test_sln', [windows_env])
  windows_env.Alias('solution', s)


sconscript_contents = """
Import('env')

env.ComponentProgram('hello', 'hello.c')
env.ComponentLibrary('foo', 'foo.c')
"""

hello_c_contents = """
#include <stdio.h>

int main() {
  printf("Hello, world!\\n");
  return 0;
}
"""

foo_c_contents = """
int test(int a, int b) {
  return a + b;
}
"""

expect_stdout = """scons: Reading SConscript files ...
scons: done reading SConscript files.
scons: Building targets ...
Adding 'test_sln - dbg|Win32' to 'test_sln.vcproj'
Adding 'test_sln - dbg|Win32' to 'test_sln.sln'
scons: done building targets.
"""

def main():
  test = TestFramework.TestFramework()

  # Test only applies to Windows
  if sys.platform not in ('win32', 'cygwin'):
    test.skip_test('This test only applies to windows.\n')
    return

  base = 'hello/'
  test.subdir(base)
  test.WriteSConscript(base + 'SConstruct', TestSConstruct)
  test.write(base + 'SConscript', sconscript_contents)
  test.write(base + 'hello.c', hello_c_contents)
  test.write(base + 'foo.c', foo_c_contents)
  test.subdir(base + 'bar')
  test.write(base + 'bar/bar.cpp', foo_c_contents)

  test.run(chdir=base, options='solution', stdout=expect_stdout)

  # Check that all solutions and projects were generated.
  test.must_exist(base + 'test_sln.sln')
  test.must_exist(base + 'test_sln.vcproj')

  test.pass_test()

if __name__ == '__main__':
  main()
