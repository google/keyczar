// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef KEYCZAR_BASE_TEST_BASE_PATHS_MAC_H_
#define KEYCZAR_BASE_TEST_BASE_PATHS_MAC_H_

// This file declares Mac-specific path keys for the base module.
// These can be used with the PathService to access various special
// directories and files.

class FilePath;

namespace keyczar {
namespace base_test {

bool GetTempDir(FilePath* path);

enum {
  FILE_EXE = 100,     // path and filename of the current executable
  FILE_MODULE,  // path and filename of the module containing the code for the
                // PathService (which could differ from FILE_EXE if the
                // PathService were compiled into a library, for example)
  DIR_SOURCE_ROOT  // Returns the root of the source tree.  This key is useful
                   // for tests that need to locate various resources.  It
                   // should not be used outside of test code.
};

}  // namespace base_test
}  // namespace keyczar

#endif  // KEYCZAR_BASE_TEST_BASE_PATHS_MAC_H_

