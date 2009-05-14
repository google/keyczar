#!/bin/bash -e
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
#
# Invoke SCons in a predictable fashion on different platforms.
#
# This script is intended (along with hammer.bat) to be the main entry
# point to the software construction toolkit.  You can either invoke this file
# as a shell script, or you can source this file in order to bring the
# functions below into your bash environment.
#
# You will need to define the env variable SCONS_DIR, which points to an
# install of SCons which contains a scons-local subdirectory.
#
# Environment variables used all the time:
#   HAMMER_OPTS        Command line options for hammer/SCons,
#                      in addition to any specified on the
#                      command line.
#
# Sample values for HAMMER_OPTS:
#   -j $(sysctl -n hw.logicalcpu)         # on Mac OS X
#   -j $(grep -c processor /proc/cpuinfo) # on Linux
#      Run parallel builds on all processor cores, unless
#      explicitly overridden on the command line.
#   -j12
#      Always run 12 builds in parallel; a good default if
#      using distcc.
#   -s -k
#      Don't print commands; keep going on build failures.

if [ "$SCONS_DIR" = "" ]
then
    export SCONS_DIR="`pwd`/tools/scons/scons-local-1.2.0.d20090223/"
fi
export SCT_DIR="$(dirname -- "${0}")"
export PYTHONPATH="$SCONS_DIR"

# Invoke scons via the software construction toolkit wrapper.
python $COVERAGE_HOOK "${SCT_DIR}/wrapper.py" $HAMMER_OPTS --site-dir="${SCT_DIR}/site_scons" "$@"
