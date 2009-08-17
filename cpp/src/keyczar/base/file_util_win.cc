// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <keyczar/base/file_util.h>

#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <time.h>

#include <string>

#include <keyczar/base/file_path.h>
#include <keyczar/base/logging.h>
#include <keyczar/base/scoped_handle.h>
#include <keyczar/base/string_util.h>
#include <keyczar/base/win_util.h>

namespace keyczar {
namespace base {

bool PathExists(const FilePath& path) {
  return (GetFileAttributes(path.value().c_str()) != INVALID_FILE_ATTRIBUTES);
}

bool DirectoryExists(const FilePath& path) {
  DWORD fileattr = GetFileAttributes(path.value().c_str());
  if (fileattr != INVALID_FILE_ATTRIBUTES)
    return (fileattr & FILE_ATTRIBUTE_DIRECTORY) != 0;
  return false;
}

FILE* OpenFile(const FilePath& filename, const char* mode) {
  std::wstring w_mode = ASCIIToWide(std::string(mode));
  FILE* file;
  if (_wfopen_s(&file, filename.value().c_str(), w_mode.c_str()) != 0) {
    return NULL;
  }
  return file;
}

FILE* OpenFile(const std::string& filename, const char* mode) {
  FILE* file;
  if (fopen_s(&file, filename.c_str(), mode) != 0) {
    return NULL;
  }
  return file;
}

int WriteFile(const FilePath& filename, const char* data, int size) {
  ScopedHandle file(CreateFile(filename.value().c_str(),
                               GENERIC_WRITE,
                               0,
                               NULL,
                               CREATE_ALWAYS,
                               0,
                               NULL));
  if (file == INVALID_HANDLE_VALUE) {
    LOG(WARNING) << "CreateFile failed for path " << filename.value() <<
        " error code=" << GetLastError() <<
        " error text=" << win_util::FormatLastWin32Error();
    return -1;
  }

  DWORD written;
  BOOL result = ::WriteFile(file, data, size, &written, NULL);
  if (result && written == size)
    return static_cast<int>(written);

  if (!result) {
    // WriteFile failed.
    LOG(WARNING) << "writing file " << filename.value() <<
        " failed, error code=" << GetLastError() <<
        " description=" << win_util::FormatLastWin32Error();
  } else {
    // Didn't write all the bytes.
    LOG(WARNING) << "wrote" << written << " bytes to " <<
        filename.value() << " expected " << size;
  }
  return -1;
}

bool Delete(const FilePath& path, bool recursive) {
  if (path.value().length() >= MAX_PATH)
    return false;

  // If we're not recursing use DeleteFile; it should be faster. DeleteFile
  // fails if passed a directory though, which is why we fall through on
  // failure to the SHFileOperation.
  if (!recursive && DeleteFile(path.value().c_str()) != 0)
    return true;

  // SHFILEOPSTRUCT wants the path to be terminated with two NULLs,
  // so we have to use wcscpy because wcscpy_s writes non-NULLs
  // into the rest of the buffer.
  wchar_t double_terminated_path[MAX_PATH + 1] = {0};
#pragma warning(suppress:4996)  // don't complain about wcscpy deprecation
  wcscpy(double_terminated_path, path.value().c_str());

  SHFILEOPSTRUCT file_operation = {0};
  file_operation.wFunc = FO_DELETE;
  file_operation.pFrom = double_terminated_path;
  file_operation.fFlags = FOF_NOERRORUI | FOF_SILENT | FOF_NOCONFIRMATION;
  if (!recursive)
    file_operation.fFlags |= FOF_NORECURSION | FOF_FILESONLY;
  int err = SHFileOperation(&file_operation);
  // Some versions of Windows return ERROR_FILE_NOT_FOUND when
  // deleting an empty directory.
  return (err == 0 || err == ERROR_FILE_NOT_FOUND);
}

bool CreateDirectory(const FilePath& full_path) {
  if (DirectoryExists(full_path))
    return true;
  int err = SHCreateDirectoryEx(NULL, full_path.value().c_str(), NULL);
  return err == ERROR_SUCCESS;
}

}  // namespace base
}  // namespace keyczar
