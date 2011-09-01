# Copyright 2011 Google Inc.
#
# Author: swillden@google.com (Shawn Willden)
#
# This is trivial Makefile whose only purpose is to make it just a
# little easier to build the C++ keyczar.  All it does is call the
# scons script.
#
# If building on a multi-core machine

JOBS ?= 1

all:
	cd ..; ./tools/swtoolkit/hammer.sh --compat -j$(JOBS)

clean:
	cd ..; ./tools/swtoolkit/hammer.sh -c -j20
