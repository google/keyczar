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
#include <keyczar/base/zlib.h>

#include <testing/gtest/include/gtest/gtest.h>

namespace keyczar {
namespace base {

TEST(ZlibTest, Basic) {
  std::string msg1 = "";
  std::string msg2 = "abcdefghijklmnopqrstuvwxyz";

  {
    std::string compressed, decompressed;
    ASSERT_TRUE(Zlib::Compress(Zlib::ZLIB, msg1, &compressed));
    ASSERT_TRUE(Zlib::Decompress(Zlib::ZLIB, compressed, &decompressed));
    EXPECT_EQ(msg1, decompressed);
  }

  {
    std::string compressed, decompressed;
    ASSERT_TRUE(Zlib::Compress(Zlib::ZLIB, msg2, &compressed));
    ASSERT_TRUE(Zlib::Decompress(Zlib::ZLIB, compressed, &decompressed));
    EXPECT_EQ(msg2, decompressed);
  }

  {
    std::string compressed, decompressed;
    ASSERT_TRUE(Zlib::Compress(Zlib::GZIP, msg1, &compressed));
    ASSERT_TRUE(Zlib::Decompress(Zlib::GZIP, compressed, &decompressed));
    EXPECT_EQ(msg1, decompressed);
  }

  {
    std::string compressed, decompressed;
    ASSERT_TRUE(Zlib::Compress(Zlib::GZIP, msg2, &compressed));
    ASSERT_TRUE(Zlib::Decompress(Zlib::GZIP, compressed, &decompressed));
    EXPECT_EQ(msg2, decompressed);
  }

  {
    std::string compressed, decompressed;
    ASSERT_TRUE(Zlib::Compress(Zlib::AUTO, msg2, &compressed));
    ASSERT_TRUE(Zlib::Decompress(Zlib::GZIP, compressed, &decompressed));
    EXPECT_EQ(msg2, decompressed);
  }

  {
    std::string compressed, decompressed;
    ASSERT_TRUE(Zlib::Compress(Zlib::GZIP, msg2, &compressed));
    ASSERT_TRUE(Zlib::Decompress(Zlib::AUTO, compressed, &decompressed));
    EXPECT_EQ(msg2, decompressed);
  }

  {
    std::string compressed, decompressed;
    ASSERT_TRUE(Zlib::Compress(Zlib::ZLIB, msg2, &compressed));
    ASSERT_TRUE(Zlib::Decompress(Zlib::AUTO, compressed, &decompressed));
    EXPECT_EQ(msg2, decompressed);
  }
}

}  // namespace base
}  // namespace keyczar
