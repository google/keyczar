// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This source code was copied from Chromium and has been modified to fit
// with Keyczar, any encountered errors are probably due to these
// modifications.

#ifndef KEYCZAR_BASE_PATH_SERVICE_H_
#define KEYCZAR_BASE_PATH_SERVICE_H_

#include <string>

#include <keyczar/base/base_paths.h>
#include <keyczar/base/build_config.h>

class FilePath;

class PathService {
 public:
  // Retrieves a path to a special directory or file and places it into the
  // string pointed to by 'path'. If you ask for a directory it is guaranteed
  // to NOT have a path separator at the end. For example, "c:\windows\temp"
  // Directories are also guaranteed to exist when this function succeeds.
  //
  // Returns true if the directory or file was successfully retrieved. On
  // failure, 'path' will not be changed.
  static bool Get(int key, FilePath* path);
  // This version, producing a wstring, is deprecated and only kept around
  // until we can fix all callers.
  static bool Get(int key, std::wstring* path);
};

#endif // KEYCZAR_BASE_PATH_SERVICE_H_

