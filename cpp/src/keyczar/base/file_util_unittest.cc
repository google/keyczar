// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <keyczar/base/file_util.h>

#if defined(OS_WIN)
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#endif

#include <fstream>
#include <iostream>
#include <set>

#include <keyczar/base/build_config.h>
#include <keyczar/base/file_path.h>
#include <keyczar/base/logging.h>
#include <keyczar/base/string_util.h>
#include <keyczar/base_test/base_paths.h>
#include <keyczar/base_test/path_service.h>

#include <testing/gtest/include/gtest/gtest.h>
#include <testing/platform_test.h>

namespace keyczar {
namespace base {

// file_util winds up using autoreleased objects on the Mac, so this needs
// to be a PlatformTest
class FileUtilTest : public PlatformTest {
 protected:
  virtual void SetUp() {
    PlatformTest::SetUp();
    // Name a subdirectory of the temp directory.
    ASSERT_TRUE(base_test::PathService::Get(base_test::DIR_TEMP, &test_dir_));
    test_dir_ = test_dir_.Append(FILE_PATH_LITERAL("FileUtilTest"));

    // Create a fresh, empty copy of this directory.
    Delete(test_dir_, true);
    CreateDirectory(test_dir_);
  }
  virtual void TearDown() {
    PlatformTest::TearDown();
    // Clean up test directory
    ASSERT_TRUE(Delete(test_dir_, true));
    ASSERT_FALSE(PathExists(test_dir_));
  }

  // the path to temporary directory used to contain the test operations
  FilePath test_dir_;
};

// Simple function to dump some text into a new file.
void CreateTextFile(const FilePath& filename,
                    const std::string& contents) {
  std::ofstream file;
  file.open(filename.value().c_str());
  ASSERT_TRUE(file.is_open());
  file << contents;
  file.close();
}

// Tests that the Delete function works as expected, especially
// the recursion flag.  Also coincidentally tests PathExists.
TEST_F(FileUtilTest, Delete) {
  // Create a file
  FilePath file_name = test_dir_.Append(FILE_PATH_LITERAL("Test File.txt"));
  CreateTextFile(file_name, "I'm cannon fodder.");

  ASSERT_TRUE(PathExists(file_name));

  FilePath subdir_path = test_dir_.Append(FILE_PATH_LITERAL("Subdirectory"));
  CreateDirectory(subdir_path);

  ASSERT_TRUE(PathExists(subdir_path));

  FilePath directory_contents = test_dir_;
#if defined(OS_WIN)
  // TODO(erikkay): see if anyone's actually using this feature of the API
  directory_contents = directory_contents.Append(FILE_PATH_LITERAL("*"));
  // Delete non-recursively and check that only the file is deleted
  ASSERT_TRUE(Delete(directory_contents, false));
  EXPECT_FALSE(PathExists(file_name));
  EXPECT_TRUE(PathExists(subdir_path));
#endif

  // Delete recursively and make sure all contents are deleted
  ASSERT_TRUE(Delete(directory_contents, true));
  EXPECT_FALSE(PathExists(file_name));
  EXPECT_FALSE(PathExists(subdir_path));
}

}  // namespace base
}  // namespace keyczar
