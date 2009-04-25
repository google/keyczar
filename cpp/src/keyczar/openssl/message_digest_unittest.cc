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
#include "testing/gtest/include/gtest/gtest.h"

#include "keyczar/openssl/message_digest.h"

namespace keyczar {

namespace openssl {

TEST(MessageDigestOpenSSL, SimpleHash) {
  std::string message("test");
  MessageDigestOpenSSL message_digest(MessageDigestImpl::SHA1);

  EXPECT_EQ(message_digest.Size(), 20);

  std::string md_value_1;
  EXPECT_TRUE(message_digest.Digest(message, &md_value_1));

  std::string md_value_2;
  EXPECT_TRUE(message_digest.Init());
  EXPECT_TRUE(message_digest.Update(message.substr(0, 2)));
  EXPECT_TRUE(message_digest.Update(message.substr(2)));
  EXPECT_TRUE(message_digest.Final(&md_value_2));

  EXPECT_EQ(md_value_1, md_value_2);

  std::string md_value_1_encoded;
  Base64WEncode(md_value_1, &md_value_1_encoded);
  std::string reference("qUqP5cyxm6YcTAhz05Hph5gvu9M");
  EXPECT_EQ(md_value_1_encoded, reference);
}

}  // namespace openssl

}  // namespace keyczar
