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
#include <keyczar/base/path_service.h>

namespace keyczar {

class KeyczarTest : public PlatformTest {
 protected:
  virtual void SetUp() {
    PlatformTest::SetUp();
    PathService::Get(base::DIR_TEMP, &temp_path_);
    temp_path_ = temp_path_.Append("keyczar");
    file_util::CreateDirectory(temp_path_);

    PathService::Get(base::DIR_SOURCE_ROOT, &data_path_);
    data_path_ = data_path_.Append("keyczar");
    data_path_ = data_path_.Append("data");

#ifdef COMPAT_KEYCZAR_06B
    data_path_ = data_path_.Append("06b");
#endif

    input_data_ = "This is some test data";
  }

  virtual void TearDown() {
    PlatformTest::TearDown();
    file_util::Delete(temp_path_, true);
  }

  // Paths used in testing.
  FilePath temp_path_;
  FilePath data_path_;
  std::string input_data_;
};

}  // namespace keyczar

#endif  // KEYCZAR_KEYCZAR_TEST_H_
