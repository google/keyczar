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

"""Software construction toolkit wrapper.

This module does setup for SCons's main routine.

Since the goal of the software construction toolkit is to _extend_ SCons and
not _wrap_ SCons, this module should contain only setup which can't be done
inside the site_init.py or tool modules; those are much better places to do
setup.
"""


import os
import sys
import SCons.Script


def FindSConstruct():
  """Find the SConstruct or main.scons file.

  Looks in the current directory for main.scons.  If not found, looks for
  SConstruct.  If neither is found, repeats in each parent directory until one
  of the files is found or root is reached.  If a match is found, specifies on
  the SCons command line via the --file option.

  If any of the SCons file options (-f, --file, --makefile, --sconstruct) are
  already specified, or the user is requesting help on SCons options (-H,
  --help-options), does nothing.
  """
  # If a SConstruct file has already been specified, or the user is asking for
  # help on SCons options, don't alter the command line.
  for arg in sys.argv:
    argname = arg.split('=')[0]
    if argname in ('-f', '--file', '--makefile', '--sconstruct', '-H',
                   '--help-options'):
      return

  while True:
    # Look for one of the valid filenames in current directory
    for try_name in ('main.scons', 'SConstruct'):
      if os.path.isfile(try_name):
        sys.argv.append('--file=%s' % try_name)
        return

    # Still here, so try one directory up
    current_dir = os.getcwd()
    os.chdir('..')
    if current_dir == os.getcwd():
      # We're at root, so give up.
      return


def PreSConsMain():
  """Do setup which can only be done prior to calling SCons's main routine.

  In general and for long-term maintainability, anything which can move from
  here to site_scons/site_init.SiteInitMain() should move there.
  """
  # Find the SConstruct
  FindSConstruct()


PreSConsMain()
SCons.Script.main()
