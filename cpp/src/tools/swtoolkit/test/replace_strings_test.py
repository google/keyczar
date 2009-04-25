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

"""Test for replace_strings.  This is a MEDIUM test."""

import TestFramework


def TestSConstruct(scons_globals):
  """Test SConstruct file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """
  # Get globals from SCons
  Environment = scons_globals['Environment']

  env = Environment(
      tools=['component_setup', 'replace_strings'],
      HOST_PLATFORMS='*',
      BUILD_TYPE='replace',
      BUILD_TYPE_DESCRIPTION='Test build for replacement',
  )
  env.Append(
      BUILD_GROUPS=['default'],
      BUILD_COMPONENTS=['SConscript'],
      REPLACE_STRINGS=[
          ('an ugly', 'a poorly presented'),
          ('ugly', 'poorly presented'),
          ('[Bb]a+d', 'restricted'),
          ('bug(s)?', '$BUGS_ARE_CALLED'),
          ('cry', 'express my feelings publicly'),
      ],
  )
  BuildComponents([env])


def TestSConscript1(scons_globals):
  """Test SConscript file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """
  # Get globals from SCons
  scons_globals['Import']('env')
  env = scons_globals['env']

  env['BUGS_ARE_CALLED'] = 'options I did not understand'
  env.ReplaceStrings('filtered.txt', 'source.txt')


def TestSConscript2(scons_globals):
  """Test SConscript file with different value for environment variable.

  Args:
    scons_globals: Global variables dict from the SConscript file.

  This verifies that
      1. ReplaceStrings() reads the environment variable.
      2. A change in the contents of the variable changes the build signature,
         causing ReplaceStrings() to be run again.
  """
  # Get globals from SCons
  scons_globals['Import']('env')
  env = scons_globals['env']

  env['BUGS_ARE_CALLED'] = 'cattle'
  env.ReplaceStrings('filtered.txt', 'source.txt')


source_txt_contents = """
The product had an ugly design.
Its menu system was particularly ugly.
It was so baaaaaad! It made me want to cry.
It had so many bugs.
Bad performance, bad error handling, bad documentation.
"""

filtered_txt_expected_contents1 = """
The product had a poorly presented design.
Its menu system was particularly poorly presented.
It was so restricted! It made me want to express my feelings publicly.
It had so many options I did not understand.
restricted performance, restricted error handling, restricted documentation.
"""

filtered_txt_expected_contents2 = """
The product had a poorly presented design.
Its menu system was particularly poorly presented.
It was so restricted! It made me want to express my feelings publicly.
It had so many cattle.
restricted performance, restricted error handling, restricted documentation.
"""


def main():
  test = TestFramework.TestFramework()

  test.subdir('replace')

  base = 'replace/'
  base_out = base + 'scons-out/replace/obj/'

  test.WriteSConscript(base + 'SConstruct', TestSConstruct)
  test.WriteSConscript(base + 'SConscript', TestSConscript1)
  test.write(base + 'source.txt', source_txt_contents)

  # Run SCons.
  test.run(chdir=base)

  # Check for test output.
  test.must_exist(base_out + 'filtered.txt')
  test.must_match(base_out + 'filtered.txt', filtered_txt_expected_contents1)

  # Write out a change in the SConscript.
  test.WriteSConscript(base + 'SConscript', TestSConscript2)

  # Run SCons.
  test.run(chdir=base)

  # Check that things change.
  test.must_match(base_out + 'filtered.txt', filtered_txt_expected_contents2)

  test.pass_test()


if __name__ == '__main__':
  main()
