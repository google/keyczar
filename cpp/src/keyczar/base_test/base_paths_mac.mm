// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <keyczar/base_test/base_paths_mac.h>

#import <Cocoa/Cocoa.h>

#include <keyczar/base/file_path.h>
#include <keyczar/base/logging.h>
#include <keyczar/base/string_util.h>
#include <keyczar/base_test/path_service.h>

namespace keyczar {
namespace base_test {

bool GetTempDir(FilePath* path) {
  NSString* tmp = NSTemporaryDirectory();
  if (tmp == nil)
    return false;
  *path = FilePath([tmp fileSystemRepresentation]);
  return true;
}

bool PathProviderMac(int key, FilePath* result) {
  std::string cur;
  switch (key) {
    case FILE_EXE:
    case FILE_MODULE: {
      NSString* path = [[NSBundle mainBundle] executablePath];
      cur = [path fileSystemRepresentation];
      break;
    }
    case DIR_SOURCE_ROOT: {
      FilePath path;
      // On the mac, unit tests execute three levels deep from the source root.
      // For example:  scons-out/<target>/tests/base_unittests
      PathService::Get(DIR_EXE, &path);
      path = path.DirName();
      path = path.DirName();
      *result = path.DirName();
      return true;
    }
    default:
      return false;
  }

  *result = FilePath(cur);
  return true;
}

}  // namespace base_test
}  // namespace keyczar
