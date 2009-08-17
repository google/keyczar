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
#include <string>

#include <testing/gtest/include/gtest/gtest.h>

#include <keyczar/base/base64w.h>
#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/key.h>
#include <keyczar/keyczar_test.h>
#include <keyczar/keyset.h>
#include <keyczar/rw/keyset_file_reader.h>
#include <keyczar/rw/keyset_file_writer.h>
#include <keyczar/rw/keyset_writer.h>

namespace keyczar {

class KeysetTest : public KeyczarTest {
};

TEST_F(KeysetTest, KeyOperations) {
  FilePath rsa_path = data_path_.Append("rsa");
  rw::KeysetJSONFileReader reader(rsa_path);

  scoped_ptr<Keyset> keyset(Keyset::Read(reader, true));
  ASSERT_TRUE(keyset.get());

  const KeysetMetadata* metadata = keyset->metadata();
  ASSERT_TRUE(metadata);

  EXPECT_EQ(metadata->GetVersion(1)->key_status(), KeyStatus::ACTIVE);
  EXPECT_EQ(metadata->GetVersion(2)->key_status(), KeyStatus::PRIMARY);
  EXPECT_EQ(keyset->primary_key_version_number(), 2);
  EXPECT_FALSE(keyset->PromoteKey(2));
  EXPECT_EQ(metadata->GetVersion(2)->key_status(), KeyStatus::PRIMARY);
  EXPECT_TRUE(keyset->DemoteKey(2));
  EXPECT_EQ(keyset->primary_key_version_number(), 0);
  EXPECT_EQ(metadata->GetVersion(1)->key_status(), KeyStatus::ACTIVE);
  EXPECT_EQ(metadata->GetVersion(2)->key_status(), KeyStatus::ACTIVE);
  EXPECT_TRUE(keyset->PromoteKey(1));
  EXPECT_EQ(keyset->primary_key_version_number(), 1);
  EXPECT_EQ(metadata->GetVersion(1)->key_status(), KeyStatus::PRIMARY);
  EXPECT_TRUE(keyset->primary_key());
  EXPECT_EQ(metadata->GetVersion(2)->key_status(), KeyStatus::ACTIVE);
  EXPECT_TRUE(keyset->PromoteKey(2));
  EXPECT_EQ(metadata->GetVersion(1)->key_status(), KeyStatus::ACTIVE);
  EXPECT_EQ(metadata->GetVersion(2)->key_status(), KeyStatus::PRIMARY);
  EXPECT_TRUE(keyset->DemoteKey(1));
  EXPECT_EQ(metadata->GetVersion(1)->key_status(), KeyStatus::INACTIVE);
  EXPECT_EQ(metadata->GetVersion(2)->key_status(), KeyStatus::PRIMARY);
  EXPECT_FALSE(keyset->DemoteKey(1));
  EXPECT_EQ(metadata->GetVersion(1)->key_status(), KeyStatus::INACTIVE);
  EXPECT_EQ(metadata->GetVersion(2)->key_status(), KeyStatus::PRIMARY);
  EXPECT_TRUE(keyset->PromoteKey(1));
  EXPECT_EQ(metadata->GetVersion(1)->key_status(), KeyStatus::ACTIVE);
  EXPECT_EQ(metadata->GetVersion(2)->key_status(), KeyStatus::PRIMARY);
  EXPECT_TRUE(keyset->PromoteKey(1));
  EXPECT_EQ(metadata->GetVersion(1)->key_status(), KeyStatus::PRIMARY);
  EXPECT_EQ(metadata->GetVersion(2)->key_status(), KeyStatus::ACTIVE);
}

TEST_F(KeysetTest, AddKeys) {
  FilePath rsa_path = data_path_.Append("rsa");
  rw::KeysetJSONFileReader reader(rsa_path);

  scoped_ptr<Keyset> keyset(Keyset::Read(reader, true));
  ASSERT_TRUE(keyset.get());

  const KeysetMetadata* metadata = keyset->metadata();
  ASSERT_TRUE(metadata);

  EXPECT_EQ(metadata->next_key_version_number(), 3);
  EXPECT_EQ(keyset->GenerateKey(KeyStatus::PRIMARY, 2048), 3);
  EXPECT_EQ(keyset->primary_key(), keyset->GetKey(3));

  EXPECT_EQ(metadata->next_key_version_number(), 4);
  EXPECT_EQ(keyset->GenerateDefaultKeySize(KeyStatus::PRIMARY), 4);
  EXPECT_EQ(keyset->primary_key(), keyset->GetKey(4));

  EXPECT_EQ(metadata->next_key_version_number(), 5);
  EXPECT_EQ(keyset->GenerateDefaultKeySize(KeyStatus::ACTIVE), 5);
  EXPECT_TRUE(keyset->GetKey(5));
  EXPECT_NE(keyset->primary_key(), keyset->GetKey(5));
}

TEST_F(KeysetTest, RevokeKeys) {
  FilePath rsa_path = data_path_.Append("rsa");
  rw::KeysetJSONFileReader reader(rsa_path);

  scoped_ptr<Keyset> keyset(Keyset::Read(reader, true));
  ASSERT_TRUE(keyset.get());

  const KeysetMetadata* metadata = keyset->metadata();
  ASSERT_TRUE(metadata);

  std::string hash1, hash2;
  EXPECT_TRUE(keyset->GetKey(1)->Hash(&hash1));
  EXPECT_TRUE(keyset->GetKey(2)->Hash(&hash2));

  EXPECT_EQ(metadata->next_key_version_number(), 3);
  EXPECT_FALSE(keyset->RevokeKey(1));
  EXPECT_FALSE(keyset->RevokeKey(2));
  EXPECT_TRUE(keyset->DemoteKey(1));
  EXPECT_TRUE(keyset->DemoteKey(2));
  EXPECT_TRUE(keyset->DemoteKey(2));
  EXPECT_TRUE(keyset->RevokeKey(1));
  EXPECT_TRUE(keyset->RevokeKey(2));

  EXPECT_FALSE(keyset->primary_key());
  EXPECT_EQ(keyset->primary_key_version_number(), 0);
  EXPECT_FALSE(keyset->GetPrimaryKeyVersion());
  EXPECT_FALSE(keyset->GetKey(1));
  EXPECT_FALSE(keyset->GetKey(2));
  EXPECT_FALSE(keyset->GetKeyFromHash(hash1));
  EXPECT_FALSE(keyset->GetKeyFromHash(hash2));

  EXPECT_EQ(keyset->GenerateKey(KeyStatus::PRIMARY, 2048), 3);
}

TEST_F(KeysetTest, KeyAccess) {
  FilePath rsa_path = data_path_.Append("rsa");
  rw::KeysetJSONFileReader reader(rsa_path);

  scoped_ptr<Keyset> keyset(Keyset::Read(reader, true));
  ASSERT_TRUE(keyset.get());

  const KeysetMetadata* metadata = keyset->metadata();
  ASSERT_TRUE(metadata);

  EXPECT_TRUE(keyset->GetKey(1));
  EXPECT_TRUE(keyset->GetKey(2));
  EXPECT_FALSE(keyset->GetKey(42));

  const Key* key1 = keyset->GetKey(1);
  std::string hash1;
  EXPECT_TRUE(key1->Hash(&hash1));
  EXPECT_EQ(key1, keyset->GetKeyFromHash(hash1));

  const Key* key2 = keyset->GetKey(2);
  std::string hash2;
  EXPECT_TRUE(key2->Hash(&hash2));
  EXPECT_EQ(key2, keyset->GetKeyFromHash(hash2));

  EXPECT_NE(key1, key2);
  EXPECT_NE(hash1, hash2);
}

TEST_F(KeysetTest, PublicKeyExport) {
  {
    FilePath rsa_path = data_path_.Append("rsa-sign");
    rw::KeysetJSONFileReader reader(rsa_path);

    scoped_ptr<Keyset> keyset(Keyset::Read(reader, true));
    ASSERT_TRUE(keyset.get());

    rw::KeysetJSONFileWriter writer(temp_path_);
    EXPECT_TRUE(keyset->PublicKeyExport(writer));
  }

  {
    rw::KeysetJSONFileReader reader(temp_path_);
    scoped_ptr<Keyset> keyset(Keyset::Read(reader, true));
    ASSERT_TRUE(keyset.get());

    const Key* public_key = keyset->GetKey(2);
    ASSERT_TRUE(public_key);

    // Read encoded signature
    std::string b64w_signature;
    FilePath signature_file = data_path_.Append("rsa-sign");
    signature_file = signature_file.Append("2.out");
    EXPECT_TRUE(base::ReadFileToString(signature_file,
                                       &b64w_signature));
    std::string signature;
    EXPECT_TRUE(base::Base64WDecode(b64w_signature, &signature));

    // Verify signature
    std::string data("This is some test data");
    data.push_back(Key::GetVersionByte());
    EXPECT_TRUE(public_key->Verify(data,
                                   signature.substr(
                                       Key::GetHeaderSize())));
  }
}

TEST_F(KeysetTest, Observers) {
  scoped_ptr<Keyset> keyset(new Keyset());
  ASSERT_TRUE(keyset.get());

  base::CreateDirectory(temp_path_.Append("observer1"));
  base::CreateDirectory(temp_path_.Append("observer2"));

  scoped_ptr<rw::KeysetWriter> file_writer1(
      new rw::KeysetJSONFileWriter(temp_path_.Append("observer1")));
  ASSERT_TRUE(file_writer1.get());
  keyset->AddObserver(file_writer1.get());

  scoped_ptr<rw::KeysetWriter> file_writer2(
      new rw::KeysetJSONFileWriter(temp_path_.Append("observer2")));
  ASSERT_TRUE(file_writer2.get());
  keyset->AddObserver(file_writer2.get());

  KeysetMetadata* metadata = NULL;
  metadata = new KeysetMetadata("Test", KeyType::RSA_PRIV,
                                KeyPurpose::DECRYPT_AND_ENCRYPT,
                                false,
                                1);
  ASSERT_TRUE(metadata);

  keyset->set_metadata(metadata);
  ASSERT_TRUE(keyset->metadata());

  EXPECT_TRUE(keyset->GenerateKey(KeyStatus::PRIMARY, 2048));
  EXPECT_TRUE(keyset->GenerateKey(KeyStatus::ACTIVE, 2048));
  EXPECT_TRUE(keyset->GenerateKey(KeyStatus::ACTIVE, 2048));

  EXPECT_TRUE(keyset->PromoteKey(3));
  EXPECT_TRUE(keyset->DemoteKey(2));
  EXPECT_TRUE(keyset->RevokeKey(2));
}

}  // namespace keyczar

