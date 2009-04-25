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

#include "keyczar/hmac_key.h"
#include "keyczar/key.h"
#include "keyczar/key_type.h"
#include "keyczar/keyset_file_reader.h"

namespace keyczar {

class HMACTest : public testing::Test {
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

  // Loads HMAC key from JSON file.
  scoped_refptr<HMACKey> LoadHMACKey(const FilePath& path,
                                     int key_version) {
    KeysetFileReader reader(path);
    scoped_ptr<Value> value(reader.ReadKey(key_version));
    EXPECT_NE(static_cast<Value*>(NULL), value.get());
    scoped_refptr<HMACKey> hmac_key(HMACKey::CreateFromValue(*value));
    CHECK(hmac_key);
    return hmac_key;
  }

  // Paths used in testing.
  FilePath temp_path_;
  FilePath data_path_;
  std::string input_data_;
};

TEST_F(HMACTest, GenerateKeyAndSign) {
  scoped_ptr<KeyType> key_type(KeyType::Create("HMAC_SHA1"));
  ASSERT_TRUE(key_type.get());

  scoped_refptr<HMACKey> hmac_key(HMACKey::GenerateKey(
                                     key_type->default_size()));
  ASSERT_TRUE(hmac_key.get());
  EXPECT_TRUE(hmac_key->GetType() &&
              hmac_key->GetType()->type() == KeyType::HMAC_SHA1);

  std::string signature;
  EXPECT_TRUE(hmac_key->Sign(input_data_, &signature));
  EXPECT_TRUE(hmac_key->Verify(input_data_, signature));
}

TEST_F(HMACTest, LoadKeyAndVerify) {
  FilePath hmac_path = data_path_.AppendASCII("hmac");
  scoped_refptr<HMACKey> hmac_key = LoadHMACKey(hmac_path, 1);

  std::string b64w_signature;
  EXPECT_TRUE(file_util::ReadFileToString(hmac_path.AppendASCII("1.out"),
                                          &b64w_signature));
  std::string signature;
  EXPECT_TRUE(Base64WDecode(b64w_signature, &signature));

  // Checks signature
  input_data_.push_back(Key::GetVersionByte());
  EXPECT_TRUE(hmac_key->Verify(input_data_,
                               signature.substr(Key::GetHeaderSize())));
}

}  // namespace keyczar
