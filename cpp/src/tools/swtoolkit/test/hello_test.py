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

"""Hello world smoke test for software construction tookit (LARGE test)."""


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


sconscript_contents = """
Import('env')

env.Program('hello', 'hello.c')
"""

hello_c_contents = """
#include <stdio.h>

int main() {
  printf("Hello, world!\\n");
  return 0;
}
"""


def main():
  test = TestFramework.TestFramework()

  test.subdir('hello')

  base = 'hello/'

  test.WriteSConscript(base + 'SConstruct', TestSConstruct)
  test.write(base + 'SConscript', sconscript_contents)
  test.write(base + 'hello.c', hello_c_contents)

  test.run(chdir=base)
  test.must_exist(base + 'scons-out/dbg/obj/hello' + TestFramework.exe_suffix)
  test.run(program=test.workpath(base + 'scons-out/dbg/obj/hello' +
                                 TestFramework.exe_suffix),
           stdout='Hello, world!\n')

  test.pass_test()

if __name__ == '__main__':
  main()
