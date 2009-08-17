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
#include <keyczar/keyset_metadata.h>
#include <keyczar/rw/keyset_file_reader.h>
#include <keyczar/rw/keyset_file_writer.h>

namespace keyczar {

class KeysetMetadataTest : public KeyczarTest {
};

TEST_F(KeysetMetadataTest, CreateFromValue) {
  FilePath aes_path = data_path_.Append("aes");

  // Deserialize
  rw::KeysetJSONFileReader reader(aes_path.value());
  scoped_ptr<Value> root_metadata(reader.ReadMetadata());
  EXPECT_NE(static_cast<Value*>(NULL), root_metadata.get());

  scoped_ptr<KeysetMetadata> metadata(KeysetMetadata::CreateFromValue(
                                          root_metadata.get()));
  EXPECT_NE(static_cast<KeysetMetadata*>(NULL), metadata.get());

  scoped_ptr<Value> root_copy(metadata->GetValue(false));
  EXPECT_NE(static_cast<Value*>(NULL), root_copy.get());

  // Serialize
  FilePath written_meta = temp_path_.Append("meta");
  rw::KeysetJSONFileWriter writer(temp_path_.value());
  EXPECT_TRUE(writer.WriteMetadata(*root_copy));
  ASSERT_TRUE(base::PathExists(written_meta));

  // Compare
  rw::KeysetJSONFileReader reader_copy(temp_path_.value());
  scoped_ptr<Value> root_metadata_copy(reader_copy.ReadMetadata());
  EXPECT_NE(static_cast<Value*>(NULL), root_metadata_copy.get());
#ifndef COMPAT_KEYCZAR_06B
  EXPECT_TRUE(root_metadata->Equals(root_metadata_copy.get()));
#endif
}

TEST_F(KeysetMetadataTest, WithoutNextKeyVersionNumber) {
  FilePath aes_path = data_path_.Append("aes-crypted");

  rw::KeysetJSONFileReader reader(aes_path.value());
  scoped_ptr<Value> root_metadata(reader.ReadMetadata());
  EXPECT_NE(static_cast<Value*>(NULL), root_metadata.get());

  scoped_ptr<KeysetMetadata> metadata(KeysetMetadata::CreateFromValue(
                                          root_metadata.get()));
  EXPECT_NE(static_cast<KeysetMetadata*>(NULL), metadata.get());
  EXPECT_EQ(metadata->next_key_version_number(), 3);
}

}  // namespace keyczar
