// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This source code was copied from Chromium and was modified, any
// encountered errors are probably due to these modifications.

// This file contains utility functions for dealing with the local
// filesystem.

#ifndef KEYCZAR_BASE_FILE_UTIL_H_
#define KEYCZAR_BASE_FILE_UTIL_H_

#include <stdio.h>

#include <string>

#include <keyczar/base/basictypes.h>
#include <keyczar/base/build_config.h>
#include <keyczar/base/file_path.h>

namespace keyczar {
namespace base {

// Returns true if the given path exists on the local filesystem,
// false otherwise.
bool PathExists(const FilePath& path);

// Returns true if the given path exists and is a directory, false otherwise.
bool DirectoryExists(const FilePath& path);

// Read the file at |path| into |contents|, returning true on success.
// Useful for unit tests.
bool ReadFileToString(const std::string& path, std::string* contents);
bool ReadFileToString(const FilePath& path, std::string* contents);

// Writes the given buffer into the file, overwriting any data that was
// previously there.  Returns the number of bytes written, or -1 on error.
int WriteFile(const std::string& filename, const char* data, int size);

bool WriteStringToFile(const std::string& path, const std::string& contents);
bool WriteStringToFile(const FilePath& path, const std::string& contents);

// Opens file
FILE* OpenFile(const std::string& filename, const char* mode);

// Closes file opened by OpenFile. Returns true on success.
bool CloseFile(FILE* file);

// Creates a directory, as well as creating any parent directories, if they
// don't exist. Returns 'true' on successful creation, or if the directory
// already exists.
bool CreateDirectory(const FilePath& full_path);

// Deletes the given path, whether it's a file or a directory.
// If it's a directory, it's perfectly happy to delete all of the
// directory's contents.  Passing true to recursive deletes
// subdirectories and their contents as well.
// Returns true if successful, false otherwise.
//
// WARNING: USING THIS WITH recursive==true IS EQUIVALENT
//          TO "rm -rf", SO USE WITH CAUTION.
bool Delete(const FilePath& path, bool recursive);

}  // namespace base
}  // namespace keyczar

#endif  // KEYCZAR_BASE_FILE_UTIL_H_
