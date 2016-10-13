#!/bin/bash
# Copyright 2013 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Building Cpp
if [[ $GTEST_DIR = "" ]]; then
  echo GTEST_DIR must be defined - see ../cpp/README for info about gtest
  exit 1
fi
cd ../cpp/src/
sh ./tools/swtoolkit/hammer.sh --mode=opt-linux --compat GTEST_DIR=$GTEST_DIR

# Building Java
cd ../../java/code
# The date is included in the java build version, so older jars get
# loaded first. Meaning older code is being tested instead of newer.
# This removes the older versions so only the most recent will remain.
rm -r target
mvn package


