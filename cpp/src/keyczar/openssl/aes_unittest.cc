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
#include <openssl/rand.h>
#include <string>

#include "base/file_path.h"
#include "base/file_util.h"
#include "base/scoped_ptr.h"
#include "testing/gtest/include/gtest/gtest.h"

#include "keyczar/cipher_mode.h"
#include "keyczar/keyczar_test.h"
#include "keyczar/openssl/aes.h"

namespace keyczar {

namespace openssl {

class AESOpenSSLTest : public KeyczarTest {
};

TEST_F(AESOpenSSLTest, EncryptAndDecrypt128) {
  unsigned char key_buffer[16];
  EXPECT_TRUE(RAND_bytes(key_buffer, 16));
  std::string key(reinterpret_cast<char*>(key_buffer), 16);

  scoped_ptr<AESOpenSSL> aes(AESOpenSSL::Create(*CipherMode::Create("CBC"),
                                                key));
  ASSERT_TRUE(aes.get());

  int iv_len = aes->GetKeySize();
  EXPECT_EQ(iv_len, 16);
  unsigned char iv_buffer[iv_len];
  EXPECT_TRUE(RAND_bytes(iv_buffer, iv_len));
  std::string iv(reinterpret_cast<char*>(iv_buffer), iv_len);

  std::string encrypted, decrypted;
  EXPECT_FALSE(aes->Encrypt(NULL, input_data_, &encrypted));
  EXPECT_TRUE(aes->Encrypt(&iv, input_data_, &encrypted));
  EXPECT_TRUE(aes->Decrypt(&iv, encrypted, &decrypted));

  EXPECT_EQ(input_data_, decrypted);
}

TEST_F(AESOpenSSLTest, EncryptAndDecrypt256) {
  unsigned char key_buffer[32];
  EXPECT_TRUE(RAND_bytes(key_buffer, 32));
  std::string key(reinterpret_cast<char*>(key_buffer), 32);

  scoped_ptr<AESOpenSSL> aes(AESOpenSSL::Create(*CipherMode::Create("CBC"),
                                                key));
  ASSERT_TRUE(aes.get());

  int iv_len = aes->GetKeySize();
  EXPECT_EQ(iv_len, 32);
  unsigned char iv_buffer[iv_len];
  EXPECT_TRUE(RAND_bytes(iv_buffer, iv_len));
  std::string iv(reinterpret_cast<char*>(iv_buffer), iv_len);

  std::string encrypted, decrypted;
  EXPECT_TRUE(aes->Encrypt(&iv, input_data_, &encrypted));
  EXPECT_TRUE(aes->Decrypt(&iv, encrypted, &decrypted));

  EXPECT_EQ(input_data_, decrypted);
}

}  // namespace openssl

}  // namespace keyczar
