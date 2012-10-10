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


all:
	$(MAKE) -C .. all

rebuild: clean all

kctests:
	$(MAKE) -C .. kctests

keyczart:
	$(MAKE) -C .. keyczart

clean:
	$(MAKE) -C .. clean
