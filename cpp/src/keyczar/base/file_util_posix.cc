// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <keyczar/base/file_util.h>

#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <stdio.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#include <vector>

#include <keyczar/base/logging.h>
#include <keyczar/base/string_util.h>

namespace {

#if defined(OS_BSD)
typedef struct stat stat_s;

static int Stat(const char* path, stat_s* buf) {
  return stat(path, buf);
}
#else
typedef struct stat64 stat_s;

static int Stat(const char* path, stat_s* buf) {
  return stat64(path, buf);
}
#endif

}  // namespace

namespace keyczar {
namespace base {

bool PathExists(const FilePath& path) {
  stat_s file_info;
  return (Stat(path.value().c_str(), &file_info) == 0);
}

bool DirectoryExists(const FilePath& path) {
  stat_s file_info;
  if (Stat(path.value().c_str(), &file_info) == 0)
    return S_ISDIR(file_info.st_mode);
  return false;
}

FILE* OpenFile(const std::string& filename, const char* mode) {
  return fopen(filename.c_str(), mode);
}

int WriteFile(const std::string& filename, const char* data, int size) {
  int fd = creat(filename.c_str(), 0666);
  if (fd < 0)
    return -1;

  // Allow for partial writes
  ssize_t bytes_written_total = 0;
  do {
    ssize_t bytes_written_partial = write(fd,
                                          data + bytes_written_total,
                                          size - bytes_written_total);
    if (bytes_written_partial < 0) {
      close(fd);
      return -1;
    }
    bytes_written_total += bytes_written_partial;
  } while (bytes_written_total < size);

  close(fd);
  return bytes_written_total;
}

// TODO(erikkay): The Windows version of this accepts paths like "foo/bar/*"
// which works both with and without the recursive flag.  I'm not sure we need
// that functionality. If not, remove from file_util_win.cc, otherwise add it
// here.
bool Delete(const FilePath& path, bool recursive) {
  const char* path_str = path.value().c_str();
  stat_s file_info;
  int test = Stat(path_str, &file_info);
  if (test != 0) {
    // The Windows version defines this condition as success.
    bool ret = (errno == ENOENT || errno == ENOTDIR);
    return ret;
  }
  if (!S_ISDIR(file_info.st_mode))
    return (unlink(path_str) == 0);
  if (!recursive)
    return (rmdir(path_str) == 0);

  bool success = true;
  int ftsflags = FTS_PHYSICAL | FTS_NOSTAT;
  char top_dir[PATH_MAX];
  if (keyczar::base::strlcpy(top_dir, path_str,
                             arraysize(top_dir)) >= arraysize(top_dir)) {
    return false;
  }
  char* dir_list[2] = { top_dir, NULL };
  FTS* fts = fts_open(dir_list, ftsflags, NULL);
  if (fts) {
    FTSENT* fts_ent = fts_read(fts);
    while (success && fts_ent != NULL) {
      switch (fts_ent->fts_info) {
        case FTS_DNR:
        case FTS_ERR:
          // log error
          success = false;
          continue;
          break;
        case FTS_DP:
          success = (rmdir(fts_ent->fts_accpath) == 0);
          break;
        case FTS_D:
          break;
        case FTS_NSOK:
        case FTS_F:
        case FTS_SL:
        case FTS_SLNONE:
          success = (unlink(fts_ent->fts_accpath) == 0);
          break;
        default:
          DCHECK(false);
          break;
      }
      fts_ent = fts_read(fts);
    }
    fts_close(fts);
  }
  return success;
}

bool CreateDirectory(const FilePath& full_path) {
  std::vector<FilePath> subpaths;

  // Collect a list of all parent directories.
  FilePath last_path = full_path;
  subpaths.push_back(full_path);
  for (FilePath path = full_path.DirName();
       path.value() != last_path.value(); path = path.DirName()) {
    subpaths.push_back(path);
    last_path = path;
  }

  // Iterate through the parents and create the missing ones.
  for (std::vector<FilePath>::reverse_iterator i = subpaths.rbegin();
       i != subpaths.rend(); ++i) {
    if (!DirectoryExists(*i)) {
      if (mkdir(i->value().c_str(), 0777) != 0)
        return false;
    }
  }
  return true;
}

}  // namespace base
}  // namespace keyczar
