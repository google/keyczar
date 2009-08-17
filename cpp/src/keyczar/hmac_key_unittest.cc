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
#include <vector>

#include <testing/gtest/include/gtest/gtest.h>

#include <keyczar/base/base64w.h>
#include <keyczar/base/logging.h>
#include <keyczar/base/ref_counted.h>
#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/values.h>
#include <keyczar/hmac_key.h>
#include <keyczar/key.h>
#include <keyczar/key_type.h>
#include <keyczar/keyczar_test.h>
#include <keyczar/rw/keyset_file_reader.h>

namespace keyczar {

class HMACTest : public KeyczarTest {
 protected:
  // Loads HMAC key from JSON file.
  scoped_refptr<HMACKey> LoadHMACKey(const FilePath& path,
                                     int key_version) {
    rw::KeysetJSONFileReader reader(path);
    scoped_ptr<Value> value(reader.ReadKey(key_version));
    EXPECT_NE(static_cast<Value*>(NULL), value.get());
    scoped_refptr<HMACKey> hmac_key(HMACKey::CreateFromValue(*value));
    CHECK(hmac_key);
    return hmac_key;
  }
};

TEST_F(HMACTest, GenerateKeyAndSign) {
#ifdef COMPAT_KEYCZAR_06B
  const KeyType::Type key_type = KeyType::HMAC_SHA1;
#else
  const KeyType::Type key_type = KeyType::HMAC;
#endif
  const std::vector<int> sizes = KeyType::CipherSizes(key_type);
  scoped_refptr<HMACKey> hmac_key;
  std::string signature;

  for (std::vector<int>::const_iterator iter = sizes.begin();
       iter != sizes.end(); ++iter) {
    hmac_key = HMACKey::GenerateKey(*iter);
    ASSERT_TRUE(hmac_key.get());

    EXPECT_TRUE(hmac_key->Sign(input_data_, &signature));
    EXPECT_TRUE(hmac_key->Verify(input_data_, signature));
  }
}

TEST_F(HMACTest, LoadKeyAndVerify) {
  FilePath hmac_path = data_path_.Append("hmac");
  scoped_refptr<HMACKey> hmac_key = LoadHMACKey(hmac_path, 1);

  std::string b64w_signature;
  EXPECT_TRUE(base::ReadFileToString(hmac_path.Append("1.out"),
                                     &b64w_signature));
  std::string signature;
  EXPECT_TRUE(base::Base64WDecode(b64w_signature, &signature));

  // Checks signature
  input_data_.push_back(Key::GetVersionByte());
  EXPECT_TRUE(hmac_key->Verify(input_data_,
                               signature.substr(Key::GetHeaderSize())));
}

}  // namespace keyczar
