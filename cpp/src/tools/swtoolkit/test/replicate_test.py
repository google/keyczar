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

"""Test for replicate.  This is a MEDIUM test."""

import TestFramework


def TestSConstruct(scons_globals):
  """Test SConstruct file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """
  # Get globals from SCons
  Environment = scons_globals['Environment']

  env = Environment(
      tools=['component_setup', 'replicate'],
      HOST_PLATFORMS='*',
      BUILD_TYPE='replicate',
      BUILD_TYPE_DESCRIPTION='Test build for replicate',
  )
  env.Append(
      BUILD_GROUPS=['default'],
      BUILD_COMPONENTS=['SConscript'],
  )
  BuildComponents([env])


def TestSConscript(scons_globals):
  """Test SConscript file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """
  # Get globals from SCons
  scons_globals['Import']('env')
  env = scons_globals['env']

  env.Replicate('.', '$MAIN_DIR/Deckard')
  env.Replicate('.', '$MAIN_DIR/Roy')
  env.Replicate('.', '$MAIN_DIR/Rachael')
  env.Replicate('Pris', '$MAIN_DIR/Pris/*')
  env.Replicate('single', 'm14')
  # TODO: make Replicate work if the $MAIN_DIR is not used and add tests to
  # test this.


def main():
  test = TestFramework.TestFramework()

  test.subdir('replicate')

  base = 'replicate/'
  base_out = base + 'scons-out/replicate/obj/'

  test.WriteSConscript(base + 'SConstruct', TestSConstruct)
  test.WriteSConscript(base + 'SConscript', TestSConscript)

  # Single layer test.
  test.subdir(base + 'Deckard')
  test.write(base + 'Deckard/m1', 'm1')
  test.write(base + 'Deckard/m2', 'm2')
  test.write(base + 'Deckard/m3', 'm3')

  # Two layer test.
  test.subdir(base + 'Roy')
  test.write(base + 'Roy/m4', 'm4')
  test.write(base + 'Roy/m5', 'm5')
  test.subdir(base + 'Roy/a')
  test.write(base + 'Roy/a/m6', 'm6')
  test.write(base + 'Roy/a/m7', 'm7')
  test.subdir(base + 'Roy/b')
  test.write(base + 'Roy/b/m8', 'm8')
  test.write(base + 'Roy/b/m9', 'm9')

  # Three layers deep.
  test.subdir(base + 'Rachael')
  test.write(base + 'Rachael/m10', 'm10')
  test.subdir(base + 'Rachael/a')
  test.subdir(base + 'Rachael/a/b')
  test.subdir(base + 'Rachael/a/b/c')
  test.write(base + 'Rachael/a/b/c/m11', 'm11')

  # Globbing.
  test.subdir(base + 'Pris')
  test.write(base + 'Pris/m12', 'm12')
  test.write(base + 'Pris/m13', 'm13')
  test.subdir(base + 'Pris/xyz')
  test.write(base + 'Pris/xyz/miss1', 'miss1')

  # Single file.
  test.write(base + 'm14', 'm14')

  # Run SCons.
  test.run(chdir=base)

  # Check one layer deep.
  test.must_match(base_out + 'Deckard/m1', 'm1')
  test.must_match(base_out + 'Deckard/m2', 'm2')
  test.must_match(base_out + 'Deckard/m3', 'm3')

  # Check two layer deep.
  test.must_match(base_out + 'Roy/m4', 'm4')
  test.must_match(base_out + 'Roy/m5', 'm5')
  test.must_match(base_out + 'Roy/a/m6', 'm6')
  test.must_match(base_out + 'Roy/a/m7', 'm7')
  test.must_match(base_out + 'Roy/b/m8', 'm8')
  test.must_match(base_out + 'Roy/b/m9', 'm9')

  # Check three layer deep.
  test.must_match(base_out + 'Rachael/m10', 'm10')
  test.must_match(base_out + 'Rachael/a/b/c/m11', 'm11')

  # Check globbing.
  test.must_match(base_out + 'Pris/m12', 'm12')
  test.must_match(base_out + 'Pris/m13', 'm13')

  # Check single file.
  test.must_match(base_out + 'single/m14', 'm14')

  test.pass_test()


if __name__ == '__main__':
  main()
