# Copyright 2011 Google Inc.
#
# Author: swillden@google.com (Shawn Willden)
#
# This is trivial Makefile whose only purpose is to make it just a
# little easier to build the C++ keyczar.  All it does is call the
# scons script.
#
# If building on a multi-core machine, set the JOBS environment variable
# to a value greater than 1 to build in parallel.

JOBS ?= 1
BUILD_CMD=cd ..; ./tools/swtoolkit/hammer.sh -j$(JOBS)

all:
	$(BUILD_CMD)

CXXFLAGS=-I.

test: test.cc

run_keyczar_unittests:
	$(BUILD_CMD) run_keyczar_unittests

clean:
	$(BUILD_CMD) -c
