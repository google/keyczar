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
#include <keyczar/base/base64w.h>
#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <keyczar/base_test/path_service.h>

#include <testing/gtest/include/gtest/gtest.h>
#include <testing/platform_test.h>

namespace keyczar {
namespace base {

class Base64WTest : public PlatformTest {
};

TEST_F(Base64WTest, Basic) {
  FilePath source_file_path;
  ASSERT_TRUE(base_test::PathService::Get(base_test::DIR_SOURCE_ROOT,
                                          &source_file_path));
  source_file_path = source_file_path.Append("keyczar");
  source_file_path = source_file_path.Append("base");
  source_file_path = source_file_path.Append("data");
  source_file_path = source_file_path.Append("base64w_unittest");
  source_file_path = source_file_path.Append("random_bytes");
  ASSERT_TRUE(PathExists(source_file_path));

  std::string input;
  ASSERT_TRUE(ReadFileToString(source_file_path, &input));

  std::string b64w_random_bytes_encoded =
      "bYxt1xwp8BjyCVNwxp120QgleK-gKjIynkOCbye6J_mPYIXjw40-XKpJL8yHP1udsgJj5WG"
      "S-SvZ9KHonKF4KqEp9keucLTTCC3PBm6AQfhkiv-yJA_8HQCBbS5xOPwMETr1jueEayeYAk"
      "qJU21apR-scOZKJU39pMEe8BTZk_rjNkR5rGhqW1F3BFn-1RvTYCH3y8L9uzWfi_cy93Qem"
      "eTuucsam6aE27ZcazT-WbD8L5L8nSCncdlggXhbnkX1j7tfYlQneZCyG1JoPXK6niNg1Bn_"
      "kyQDWFhhM3DkpFH-pf-PafwvV9n_xrwlw5OfxSLFtWzLpTNpQTZhJkX4pqiGuu8385RNYfp"
      "ZH4fNIEKlFSf3xb6W9lwgT7N6FWBzx6OlsKzotmv0ZdwgcmrOm5iGyGHTBcjLt6q0GXwkhB"
      "UuypeKri-ZKlmLmZgS72oxLyptUAe4CiQ6ldYj6eoRYE5kvPkfUtX-jIMJvRmM1H_tI-7QY"
      "KaC0xXC0kf73CjdQ8s_RZetYkgO0DhybqU78gKDBRBVuk25gTUVuWuauLXUhy6lF6I2T1Rg"
      "uPLaweCHHrrow_ah8r9ou9V-bryJwWXB9IbxIMi5j6oTuNTTvlebq6AYhirnCqM7EYWDEjn"
      "gGdhauGeF0sxG4LM6EvIIqdKAac6waQsrlFU97n_C8BM";

  std::string encoded, decoded;
  EXPECT_TRUE(Base64WEncode(input, &encoded));
  EXPECT_EQ(b64w_random_bytes_encoded, encoded);

  EXPECT_TRUE(Base64WDecode(encoded, &decoded));
  EXPECT_EQ(input, decoded);
}

TEST_F(Base64WTest, Decode) {
  std::string b64w_encoded_no_padding =
      "ADYufZXrex-m4jN-_3rkB06rEZN4GgMl_zsCW_WGZuf4DsKApY3-kiwnYCTjO7igMqLuDWh"
      "2qx2kiTVwBsPgUSkLzJXoLmAPswVe6-RWV-lQRFkjUhJqAyC3Qpjl0PYtaFwSf4oj_bv-ix"
      "zOTddD1e_KsRNKQG3qspWKkRlh3pk46ZDTg9eb1j7xWPf_2E40hmt3ZmOggG4OJFka6DZKF"
      "VWgolw755uvIHuF6E5IuVPnFeuColYKZqdJxyQTrrSRBDoL9iwj5PSojMQxy9pqQrQsQovG"
      "aHco7wftEUika5ySJmwSjClpaXlQcG97_Y2VTwsvIHfcWtbnU5g3G0JKFzE";

  std::string b64w_encoded =
      "ADYufZXrex-m4jN-_3rkB06rEZN4GgMl_zsCW_WGZuf4DsKApY3-kiwnYCTjO7igMqLuDWh"
      "2qx2kiTVwBsPgUSkLzJXoLmAPswVe6-RWV-lQRFkjUhJqAyC3Qpjl0PYtaFwSf4oj_bv-ix"
      "zOTddD1e_KsRNKQG3qspWKkRlh3pk46ZDTg9eb1j7xWPf_2E40hmt3ZmOggG4OJFka6DZKF"
      "VWgolw755uvIHuF6E5IuVPnFeuColYKZqdJxyQTrrSRBDoL9iwj5PSojMQxy9pqQrQsQovG"
      "aHco7wftEUika5ySJmwSjClpaXlQcG97_Y2VTwsvIHfcWtbnU5g3G0JKFzE==";

  std::string b64w_encoded_ws =
      "ADYufZXrex-m4jN-_3rkB06rEZN4GgMl_zsCW_WGZuf4DsKApY3-kiwnYCTjO7igMqLuDWh"
      "2qx2kiTVwBsPgUSkLzJXoLmAPswVe6-RWV-lQRFkjUhJqAyC3Qpjl0PYtaFwSf4oj_bv-ix"
      "zOTddD1e_KsRNKQG3qspWKkRlh3pk46ZDTg9eb1j7xWPf_2E40hmt3ZmOggG4OJFka6DZKF"
      "VWgolw755uvIHuF6E5IuVPnFeuColYKZqdJxyQTrrSRBDoL9iwj5PSojMQxy9pqQrQsQovG"
      "aHco7wftEUika5ySJmwSjClpaXlQcG97_Y2VTwsvIHfcWtbnU5g3G0JKFzE==";

  std::string decoded;
  EXPECT_TRUE(Base64WDecode(b64w_encoded_no_padding, &decoded));
  EXPECT_TRUE(Base64WDecode(b64w_encoded, &decoded));
  EXPECT_TRUE(Base64WDecode(b64w_encoded_ws, &decoded));
}

}  // namespace base
}  // namespace keyczar
