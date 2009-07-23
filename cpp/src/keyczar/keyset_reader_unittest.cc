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
#include <testing/gtest/include/gtest/gtest.h>

#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <keyczar/base/values.h>
#include <keyczar/keyczar_test.h>
#include <keyczar/keyset_file_reader.h>

namespace keyczar {

class KeysetReaderTest : public KeyczarTest {
};

TEST_F(KeysetReaderTest, ValidRead) {
  FilePath path = data_path_.Append("aes");

  KeysetFileReader reader(path.value());
  ASSERT_TRUE(file_util::PathExists(path.AppendASCII("meta")));
  EXPECT_NE(static_cast<Value*>(NULL), reader.ReadMetadata());
  ASSERT_TRUE(file_util::PathExists(path.AppendASCII("1")));
  EXPECT_NE(static_cast<Value*>(NULL), reader.ReadKey(1));
  ASSERT_TRUE(file_util::PathExists(path.AppendASCII("2")));
  EXPECT_NE(static_cast<Value*>(NULL), reader.ReadKey(2));
  ASSERT_FALSE(file_util::PathExists(path.AppendASCII("3")));
  EXPECT_EQ(static_cast<Value*>(NULL), reader.ReadKey(3));
}

}  // namespace keyczar
