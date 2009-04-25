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

#include "base/base64w.h"
#include "base/logging.h"
#include "base/ref_counted.h"
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/path_service.h"
#include "base/scoped_ptr.h"
#include "base/values.h"
#include "testing/gtest/include/gtest/gtest.h"

#include "keyczar/aes_key.h"
#include "keyczar/keyset_file_reader.h"
#include "keyczar/keyset_file_writer.h"

namespace keyczar {

class AESTest : public testing::Test {
 protected:
  virtual void SetUp() {
    PathService::Get(base::DIR_TEMP, &temp_path_);
    temp_path_ = temp_path_.AppendASCII("keyczar");
    file_util::CreateDirectory(temp_path_);

    PathService::Get(base::DIR_SOURCE_ROOT, &data_path_);
    data_path_ = data_path_.AppendASCII("keyczar");
    data_path_ = data_path_.AppendASCII("data");

    input_data_ = "This is some test data";
  }

  virtual void TearDown() {
    file_util::Delete(temp_path_, true);
  }

  // Loads AES key from JSON file.
  scoped_refptr<AESKey> LoadAESKey(const FilePath& path,
                                          int key_version) {
    KeysetFileReader reader(path);
    scoped_ptr<Value> value(reader.ReadKey(key_version));
    EXPECT_NE(static_cast<Value*>(NULL), value.get());
    scoped_refptr<AESKey> aes_key(AESKey::CreateFromValue(*value));
    CHECK(aes_key);
    return aes_key;
  }

  // Paths used in testing.
  FilePath temp_path_;
  FilePath data_path_;
  std::string input_data_;
};

TEST_F(AESTest, GenerateKeyAndEncrypt) {
  int size = 192;

  // Generates a new secret key
  scoped_refptr<AESKey> aes_key(AESKey::GenerateKey(size));
  ASSERT_TRUE(aes_key.get());
  EXPECT_TRUE(aes_key->GetType() &&
              aes_key->GetType()->type() == KeyType::AES);

  // Attempts to encrypt and decrypt input data.
  std::string encrypted_data;
  EXPECT_TRUE(aes_key->Encrypt(input_data_, &encrypted_data));

  std::string decrypted_data;
  EXPECT_TRUE(aes_key->Decrypt(encrypted_data, &decrypted_data));
  EXPECT_EQ(input_data_, decrypted_data);
}

TEST_F(AESTest, LoadKeyAndDecrypt) {
  FilePath aes_path = data_path_.AppendASCII("aes");
  scoped_refptr<AESKey> aes_key = LoadAESKey(aes_path, 1);

  // Try to decrypt corresponding data file
  std::string b64w_encrypted_data;
  EXPECT_TRUE(file_util::ReadFileToString(aes_path.AppendASCII("1.out"),
                                          &b64w_encrypted_data));
  std::string encrypted_data;
  EXPECT_TRUE(Base64WDecode(b64w_encrypted_data, &encrypted_data));
  std::string decrypted_data;
  EXPECT_TRUE(aes_key->Decrypt(encrypted_data, &decrypted_data));

  // Compares clear texts
  EXPECT_EQ(decrypted_data, input_data_);
}

TEST_F(AESTest, GenerateKeyDumpAndCompare) {
  int size = 256;

  // Generates a new secret key
  scoped_refptr<AESKey> aes_key(AESKey::GenerateKey(size));
  ASSERT_TRUE(aes_key.get());

  // Dumps this secret key into temporary path
  KeysetFileWriter writer(temp_path_);
  EXPECT_TRUE(writer.WriteKey(aes_key->GetValue(), 1));
  ASSERT_TRUE(file_util::PathExists(temp_path_.Append("1")));

  // Loads this key
  scoped_refptr<AESKey> dumped_key = LoadAESKey(temp_path_, 1);

  EXPECT_EQ(dumped_key->aes_impl()->GetKey(), aes_key->aes_impl()->GetKey());

  std::string hash1, hash2;
  EXPECT_TRUE(dumped_key->Hash(&hash1));
  EXPECT_TRUE(dumped_key->Hash(&hash2));
  EXPECT_EQ(hash1, hash2);

  EXPECT_EQ(dumped_key->hmac_key()->hmac_impl()->GetKey(),
            aes_key->hmac_key()->hmac_impl()->GetKey());
}

}  // namespace keyczar
