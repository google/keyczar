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

#include <keyczar/aes_key.h>
#include <keyczar/base/base64w.h>
#include <keyczar/base/logging.h>
#include <keyczar/base/ref_counted.h>
#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/values.h>
#include <keyczar/keyczar_test.h>
#include <keyczar/rw/keyset_file_reader.h>
#include <keyczar/rw/keyset_file_writer.h>

namespace keyczar {

class AESTest : public KeyczarTest {
 protected:
  // Loads AES key from JSON file.
  scoped_refptr<AESKey> LoadAESKey(const FilePath& path,
                                          int key_version) {
    rw::KeysetJSONFileReader reader(path);
    scoped_ptr<Value> value(reader.ReadKey(key_version));
    EXPECT_NE(static_cast<Value*>(NULL), value.get());
    scoped_refptr<AESKey> aes_key(AESKey::CreateFromValue(*value));
    CHECK(aes_key);
    return aes_key;
  }
};

TEST_F(AESTest, GenerateKeyAndEncrypt) {
  const std::vector<int> sizes = KeyType::CipherSizes(KeyType::AES);
  scoped_refptr<AESKey> aes_key;

  for (std::vector<int>::const_iterator iter = sizes.begin();
       iter != sizes.end(); ++iter) {
    // Generates a new secret key
    aes_key = AESKey::GenerateKey(*iter);
    ASSERT_TRUE(aes_key.get());

    // Attempts to encrypt and decrypt input data.
    std::string encrypted_data;
    EXPECT_TRUE(aes_key->Encrypt(input_data_, &encrypted_data));

    std::string decrypted_data;
    EXPECT_TRUE(aes_key->Decrypt(encrypted_data, &decrypted_data));
    EXPECT_EQ(input_data_, decrypted_data);
  }
}

TEST_F(AESTest, LoadKeyAndDecrypt) {
  FilePath aes_path = data_path_.Append("aes");
  scoped_refptr<AESKey> aes_key = LoadAESKey(aes_path, 1);

  // Try to decrypt corresponding data file
  std::string b64w_encrypted_data;
  EXPECT_TRUE(base::ReadFileToString(aes_path.Append("1.out"),
                                     &b64w_encrypted_data));
  std::string encrypted_data;
  EXPECT_TRUE(base::Base64WDecode(b64w_encrypted_data, &encrypted_data));
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
  rw::KeysetJSONFileWriter writer(temp_path_);
  scoped_ptr<Value> value(aes_key->GetValue());
  EXPECT_TRUE(writer.WriteKey(*value, 1));
  ASSERT_TRUE(base::PathExists(temp_path_.Append("1")));

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
