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

#include "base/file_path.h"
#include "base/file_util.h"
#include "base/path_service.h"
#include "base/scoped_ptr.h"
#include "testing/gtest/include/gtest/gtest.h"

#include "keyczar/openssl/message_digest.h"
#include "keyczar/openssl/rsa.h"

namespace keyczar {

namespace openssl {

class RSAOpenSSLTest : public testing::Test {
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

  // Paths used in testing.
  FilePath temp_path_;
  FilePath data_path_;
  std::string input_data_;
};

TEST_F(RSAOpenSSLTest, GenerateKeyAndEncrypt) {
  int size = 1024;
  scoped_ptr<RSAOpenSSL> rsa(RSAOpenSSL::GenerateKey(size));
  ASSERT_TRUE(rsa.get());

  std::string encrypted_data;
  EXPECT_TRUE(rsa->Encrypt(input_data_, &encrypted_data));
  EXPECT_EQ(static_cast<int>(encrypted_data.length()), size / 8);
  std::string decrypted_data;
  EXPECT_TRUE(rsa->Decrypt(encrypted_data, &decrypted_data));
  EXPECT_EQ(input_data_, decrypted_data);
}

TEST(RSAOpenSSL, CreateKeyAndCompare) {
  int size = 1024;
  scoped_ptr<RSAOpenSSL> rsa_generated(RSAOpenSSL::GenerateKey(size));
  ASSERT_TRUE(rsa_generated.get());

  RSAImpl::RSAIntermediateKey intermediate_key;
  ASSERT_TRUE(rsa_generated->GetAttributes(&intermediate_key));
  scoped_ptr<RSAOpenSSL> rsa_created(RSAOpenSSL::Create(intermediate_key,
                                                        true));
  ASSERT_TRUE(rsa_created.get());
  EXPECT_TRUE(rsa_generated->Equals(*rsa_created));

  RSAImpl::RSAIntermediateKey intermediate_public_key;
  ASSERT_TRUE(rsa_generated->GetPublicAttributes(&intermediate_public_key));
  scoped_ptr<RSAOpenSSL> rsa_public(RSAOpenSSL::Create(intermediate_public_key,
                                                       false));
  ASSERT_TRUE(rsa_public.get());
  rsa_generated->private_key_ = false;
  EXPECT_TRUE(rsa_generated->Equals(*rsa_public));
}

TEST_F(RSAOpenSSLTest, GenerateKeyAndSign) {
  MessageDigestOpenSSL digest(MessageDigestImpl::SHA1);
  std::string message_digest;
  EXPECT_TRUE(digest.Digest(input_data_, &message_digest));

  int size = 1024;
  scoped_ptr<RSAOpenSSL> rsa(RSAOpenSSL::GenerateKey(size));
  ASSERT_TRUE(rsa.get());

  std::string signed_message_digest;
  EXPECT_TRUE(rsa->Sign(message_digest, &signed_message_digest));
  EXPECT_EQ(static_cast<int>(signed_message_digest.length()), size / 8);
  EXPECT_TRUE(rsa->Verify(message_digest, signed_message_digest));
}

TEST_F(RSAOpenSSLTest, ExportToPEMFile) {
  int size = 1024;
  scoped_ptr<RSAOpenSSL> rsa(RSAOpenSSL::GenerateKey(size));
  ASSERT_TRUE(rsa.get());

  FilePath pem_file = temp_path_.Append("1_pub.pem");
  rsa->WriteKeyToPEMFile(pem_file.value());
  EXPECT_TRUE(file_util::PathExists(pem_file));
}

}  // namespace openssl

}  // namespace keyczar
