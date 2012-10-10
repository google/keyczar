# Copyright 2011 Google Inc.
#
# Author: swillden@google.com (Shawn Willden)
#
# This is trivial Makefile whose only purpose is to make it just a
# little easier to build the C++ keyczar.  All it does is call the
# scons script.
#
# If building on a multi-core machine, set the environment variable
# JOBS to the number of parallel build threads you want to use
# (generally $NUM_CPUS * 1.5 is a good choice).
#
# If you want to create a debuggable build, set environment variable
# DEBUG to 1
JOBS ?= 1
ifeq ($(DEBUG),1)
    HAMMER_OPTS+="CXXFLAGS=-g LDFLAGS=-g"
endif

# Filter out all MAKE flags other than -s and -k, because hammer would be
# confused by them.  Note that -s will hide the "Entering directory"
# notifications needed by EMACS to figure out where to find source files
# mentioned in error messages, so perhaps we should filter that as well.
FILTERED_MAKEFLAGS:=$(shell echo $(MAKEFLAGS) | sed 's/[^ks]//g')

OPTS=--compat -j$(JOBS) HAMMER_OPTS=$(HAMMER_OPTS) -$(FILTERED_MAKEFLAGS)

BUILD_CMD=./tools/swtoolkit/hammer.sh $(OPTS)

all:
	$(BUILD_CMD)

kctests:
	$(BUILD_CMD) run_keyczar_unittests

keyczart:
	$(BUILD_CMD) keyczart

clean:
	$(BUILD_CMD) -c
