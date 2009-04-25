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

import sys
import TestFramework


def TestSConstruct(scons_globals):
  """Test SConstruct file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """

  # Get globals from SCons
  Environment = scons_globals['Environment']

  env = Environment(tools=['component_setup', 'seven_zip'])
  env.PrependENVPath('PATH', env.File(sys.executable).dir.abspath)
  env.Replace(SEVEN_ZIP='python $FAKE7Z',
              FAKE7Z=env.File('fake7z.py').abspath)

  # Test extract
  print 'Will extract:', env.Extract7zip('outdir/dummy_file', 'foodir/foo.7z')

  # Test archive
  env.Compress7zip('comp.7z', ['bardir/bar1'])
  env.Archive7zip('arch.7z', [env.Dir('bardir')])


foo7z_contents = """
7-Zip 4.23  Copyright (c) 1999-2005 Igor Pavlov  2005-06-29

Listing archive: test.zip

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------
2009-02-06 16:59:30 .R..A           46           44  apple
2009-03-23 13:58:16 D...A        30590         3198  berry
2009-03-30 13:17:18 .R..A          443          139  cherry
2009-03-30 13:16:50 DR..A          443          139  daquiri
2009-02-06 16:59:30 .R..A           81           75  eggplant
------------------- ----- ------------ ------------  ------------
                                 31603         3595  5 files
"""

fake7z_contents = """#!/usr/bin/python2.4

import sys

if sys.argv[1] == 'l':
  f = open(sys.argv[2], 'rt')
  for l in f:
    print l.strip()
  f.close()

"""


expect_stdout = r"""scons: Reading SConscript files ...
Will extract: ['outdir\\apple', 'outdir\\cherry', 'outdir\\eggplant']
scons: done reading SConscript files.
scons: Building targets ...
cd bardir && python WORKDIR\test\fake7z.py a -t7z -mx0 WORKDIR\test\arch.7z ./
cd bardir && python WORKDIR\test\fake7z.py a -t7z -mx9 WORKDIR\test\comp.7z bar1
GenerateDoxyDeps(["doxy_deps.txt"], [])
Building list of object files...
Building dependency lists for source directories...
Writing doxy dependencies to WORKDIR\test\doxy_deps.txt...
Wrote dependency information for 0 directories.

Delete("outdir")
python WORKDIR\test\fake7z.py x foodir\foo.7z -o"outdir"
scons: done building targets.
"""


def main():
  test = TestFramework.TestFramework()

  if sys.platform not in ['win32', 'cygwin']:
    test.skip_test('This test is only for windows.\n')
    return

  base = 'test/'
  test.subdir(base)

  test.WriteSConscript(base + 'SConstruct', TestSConstruct)

  test.subdir(base + 'foodir/')
  test.write(base + 'foodir/foo.7z', foo7z_contents)

  test.subdir(base + 'bardir/')

  test.write(base + 'bardir/bar1', 'Sample input file 1')
  test.write(base + 'bardir/bar2', 'Sample input file 2')
  test.write(base + 'fake7z.py', fake7z_contents)

  test.run(chdir=base, options='.',
           stdout=expect_stdout.replace('WORKDIR', test.workdir))

  test.pass_test()

if __name__ == '__main__':
  main()
