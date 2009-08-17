// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <keyczar/base/file_util.h>

#if defined(OS_WIN)
#include <io.h>
#endif
#include <stdio.h>

namespace keyczar {
namespace base {

bool ReadFileToString(const std::string& path, std::string* contents) {
  FILE* file = OpenFile(path, "rb");
  if (!file) {
    return false;
  }

  char buf[1 << 16];
  size_t len;
  while ((len = fread(buf, 1, sizeof(buf), file)) > 0) {
    contents->append(buf, len);
  }
  CloseFile(file);

  return true;
}

bool ReadFileToString(const FilePath& path, std::string* contents) {
  return ReadFileToString(path.value(), contents);
}

bool WriteStringToFile(const std::string& path, const std::string& contents) {
  int contents_size = contents.size();
  if (WriteFile(path, contents.data(), contents_size) != contents_size)
    return false;
  return true;
}

bool WriteStringToFile(const FilePath& path, const std::string& contents) {
  return WriteStringToFile(path.value(), contents);
}

bool CloseFile(FILE* file) {
  if (file == NULL)
    return true;
  return fclose(file) == 0;
}

}  // namespace base
}  // namespace keyczar
