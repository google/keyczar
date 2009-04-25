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
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/path_service.h"
#include "base/values.h"
#include "testing/gtest/include/gtest/gtest.h"

#include "keyczar/keyset_metadata.h"
#include "keyczar/keyset_file_reader.h"
#include "keyczar/keyset_file_writer.h"

namespace keyczar {

TEST(KeysetMetadata, CreateFromValue) {
  FilePath aes_path;
  ASSERT_TRUE(PathService::Get(base::DIR_SOURCE_ROOT, &aes_path));
  aes_path = aes_path.AppendASCII("keyczar");
  aes_path = aes_path.AppendASCII("data");
  aes_path = aes_path.AppendASCII("aes");

  // Deserialize
  KeysetFileReader reader(aes_path.value());
  scoped_ptr<Value> root_metadata(reader.ReadMetadata());
  EXPECT_NE(static_cast<Value*>(NULL), root_metadata.get());

  scoped_ptr<KeysetMetadata> metadata(KeysetMetadata::CreateFromValue(
                                          root_metadata.get()));
  EXPECT_NE(static_cast<KeysetMetadata*>(NULL), metadata.get());

  scoped_ptr<Value> root_copy(metadata->GetValue(false));
  EXPECT_NE(static_cast<Value*>(NULL), root_copy.get());

  // Serialize
  FilePath written_path;
  ASSERT_TRUE(PathService::Get(base::DIR_TEMP, &written_path));

  FilePath written_meta = written_path.AppendASCII("meta");
  ASSERT_FALSE(file_util::PathExists(written_meta));
  KeysetFileWriter writer(written_path.value());
  EXPECT_TRUE(writer.WriteMetadata(root_copy.get()));
  ASSERT_TRUE(file_util::PathExists(written_meta));

  // Compare
  KeysetFileReader reader_copy(written_path.value());
  scoped_ptr<Value> root_metadata_copy(reader_copy.ReadMetadata());
  EXPECT_NE(static_cast<Value*>(NULL), root_metadata_copy.get());
  EXPECT_TRUE(root_metadata->Equals(root_metadata_copy.get()));
  EXPECT_TRUE(file_util::Delete(written_meta, false));
}

TEST(KeysetMetadata, WithoutNextKeyVersionNumber) {
  FilePath aes_path;
  ASSERT_TRUE(PathService::Get(base::DIR_SOURCE_ROOT, &aes_path));
  aes_path = aes_path.AppendASCII("keyczar");
  aes_path = aes_path.AppendASCII("data");
  aes_path = aes_path.AppendASCII("aes-crypted");

  KeysetFileReader reader(aes_path.value());
  scoped_ptr<Value> root_metadata(reader.ReadMetadata());
  EXPECT_NE(static_cast<Value*>(NULL), root_metadata.get());

  scoped_ptr<KeysetMetadata> metadata(KeysetMetadata::CreateFromValue(
                                          root_metadata.get()));
  EXPECT_NE(static_cast<KeysetMetadata*>(NULL), metadata.get());
  EXPECT_EQ(metadata->next_key_version_number(), 3);
}

}  // namespace keyczar
