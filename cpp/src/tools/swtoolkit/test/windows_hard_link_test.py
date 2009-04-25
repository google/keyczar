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

"""Test for windows_hard_link.  These are MEDIUM tests."""

import sys
import TestFramework


def TestSConstruct(scons_globals):
  """Test SConstruct file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """

  # Get globals from SCons
  Environment = scons_globals['Environment']
  Touch = scons_globals['Touch']
  Chmod = scons_globals['Chmod']

  env = Environment(tools=['component_setup', 'windows_hard_link'])

  # Create a file in SCons, so it has a builder
  env.Command('b.txt', [], Touch('$TARGET'))

  # Create a read-only file with a builder
  env.Command('c.txt', [], [Touch('$TARGET'), Chmod('$TARGET', 0444)])

  # Install copies of the files
  n = env.InstallAs(target=['a2.txt', 'b2.txt', 'c2.txt'],
                    source=['a.txt', 'b.txt', 'c.txt'])
  # Build those by default
  env.Default(n)


def AppendToFile(filename):
  """Appends 'modified' to the file.

  Args:
    filename: Name of file to modify.
  """
  f = open(filename, 'at')
  f.write('modified')
  f.close()


def main():
  test = TestFramework.TestFramework()

  if sys.platform != 'win32':
    test.skip_test('This test only applies to win32.\n')
    return

  test.subdir('windows_hard_link')
  base = 'windows_hard_link/'

  test.WriteSConscript(base + '/SConstruct', TestSConstruct)
  test.write(base + 'a.txt', 'File A\n')

  test.run(chdir=base)

  # Check expected file contents
  test.must_match(base + 'a.txt', 'File A\n')
  test.must_match(base + 'b.txt', '')
  test.must_match(base + 'c.txt', '')
  test.must_match(base + 'a2.txt', 'File A\n')
  test.must_match(base + 'b2.txt', '')
  test.must_match(base + 'c2.txt', '')

  # To tell if the files are hard links, need to modify the copies
  AppendToFile(test.workpath(base + 'a2.txt'))
  AppendToFile(test.workpath(base + 'b2.txt'))
  AppendToFile(test.workpath(base + 'c2.txt'))

  # Make sure the destination files were modified
  test.must_match(base + 'a2.txt', 'File A\nmodified')
  test.must_match(base + 'b2.txt', 'modified')
  test.must_match(base + 'c2.txt', 'modified')

  # File A should not have been hard-linked, since it does not have a builder
  test.must_match(base + 'a.txt', 'File A\n')
  # File B should have been altered, since it and b2.txt are hard-linked
  test.must_match(base + 'b.txt', 'modified')
  # File C should not have been altered, since it's read-only
  test.must_match(base + 'c.txt', '')

  test.pass_test()

if __name__ == '__main__':
  main()
