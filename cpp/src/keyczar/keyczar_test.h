// Copyright 2009 Sebastien Martini (seb@dbzteam.org)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#ifndef KEYCZAR_KEYCZAR_TEST_H_
#define KEYCZAR_KEYCZAR_TEST_H_
#include <string>

#include <testing/gtest/include/gtest/gtest.h>
#include <testing/platform_test.h>

#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <keyczar/base/logging.h>
#include <keyczar/base_test/path_service.h>

namespace keyczar {

class KeyczarTest : public PlatformTest {
 protected:
  virtual void SetUp() {
    PlatformTest::SetUp();
    base_test::PathService::Get(base_test::DIR_TEMP, &temp_path_);
    temp_path_ = temp_path_.Append("keyczar");
    base::CreateDirectory(temp_path_);

    base_test::PathService::Get(base_test::DIR_SOURCE_ROOT, &data_path_);
    data_path_ = data_path_.Append("keyczar");
    data_path_ = data_path_.Append("data");

#ifdef COMPAT_KEYCZAR_06B
    data_path_ = data_path_.Append("06b");
#endif

    input_data_ = "This is some test data";
    hidden_data_ = "This is some hidden data";
  }

  virtual void TearDown() {
    PlatformTest::TearDown();
    base::Delete(temp_path_, true);
  }

  // Paths used in testing.
  FilePath temp_path_;
  FilePath data_path_;
  std::string input_data_;
  std::string hidden_data_;

  // Common test routines
  void TestSignAndVerify(const std::string& sign_key,
                         const std::string& verify_key) const;

  void TestAttachedSignAndVerify(const std::string& sign_key,
                                 const std::string& verify_key) const;

  void TestSignAndVerifyUnversioned(const std::string& sign_key,
                                    const std::string& verify_key) const;

  // Utility methods
  void ReadDataFile(const std::string& filename, std::string* content) const;
};

}  // namespace keyczar

#endif  // KEYCZAR_KEYCZAR_TEST_H_
