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
#include "keyczar/openssl/dsa.h"

namespace keyczar {

namespace openssl {

class DSAOpenSSLTest : public testing::Test {
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

TEST(DSAOpenSSL, CreateKeyAndCompare) {
  int size = 1024;
  scoped_ptr<DSAOpenSSL> dsa_generated(DSAOpenSSL::GenerateKey(size));
  ASSERT_TRUE(dsa_generated.get());

  DSAImpl::DSAIntermediateKey intermediate_key;
  ASSERT_TRUE(dsa_generated->GetAttributes(&intermediate_key));
  scoped_ptr<DSAOpenSSL> dsa_created(DSAOpenSSL::Create(intermediate_key,
                                                        true));
  ASSERT_TRUE(dsa_created.get());
  EXPECT_TRUE(dsa_generated->Equals(*dsa_created));

  DSAImpl::DSAIntermediateKey intermediate_public_key;
  ASSERT_TRUE(dsa_generated->GetPublicAttributes(&intermediate_public_key));
  scoped_ptr<DSAOpenSSL> dsa_public(DSAOpenSSL::Create(intermediate_public_key,
                                                       false));
  ASSERT_TRUE(dsa_public.get());
  dsa_generated->private_key_ = false;
  EXPECT_TRUE(dsa_generated->Equals(*dsa_public));
}

TEST_F(DSAOpenSSLTest, GenerateKeyAndSign) {
  MessageDigestOpenSSL digest(MessageDigestImpl::SHA1);
  std::string message_digest;
  EXPECT_TRUE(digest.Digest(input_data_, &message_digest));

  int size = 1024;
  scoped_ptr<DSAOpenSSL> dsa(DSAOpenSSL::GenerateKey(size));
  ASSERT_TRUE(dsa.get());

  std::string signed_message_digest;
  EXPECT_TRUE(dsa->Sign(message_digest, &signed_message_digest));
  EXPECT_TRUE(dsa->Verify(message_digest, signed_message_digest));
}

TEST_F(DSAOpenSSLTest, ExportToPEMFile) {
  int size = 1024;
  scoped_ptr<DSAOpenSSL> dsa(DSAOpenSSL::GenerateKey(size));
  ASSERT_TRUE(dsa.get());

  FilePath pem_file = temp_path_.Append("1_pub.pem");
  dsa->WriteKeyToPEMFile(pem_file.value());
  EXPECT_TRUE(file_util::PathExists(pem_file));
}

}  // namespace openssl

}  // namespace keyczar
