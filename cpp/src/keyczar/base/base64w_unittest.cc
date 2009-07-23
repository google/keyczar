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
#include <keyczar/base/file_util.h>
#include <keyczar/base/path_service.h>

#include <testing/gtest/include/gtest/gtest.h>

TEST(Base64WTest, Basic) {
  std::wstring source_file_path;
  ASSERT_TRUE(PathService::Get(base::DIR_SOURCE_ROOT, &source_file_path));
  file_util::AppendToPath(&source_file_path, L"keyczar");
  file_util::AppendToPath(&source_file_path, L"base");
  file_util::AppendToPath(&source_file_path, L"data");
  file_util::AppendToPath(&source_file_path, L"base64w_unittest");
  file_util::AppendToPath(&source_file_path, L"random_bytes");
  ASSERT_TRUE(file_util::PathExists(source_file_path));

  std::string input;
  ASSERT_TRUE(file_util::ReadFileToString(source_file_path, &input));

  std::string b64w_random_bytes_encoded = "bYxt1xwp8BjyCVNwxp120QgleK-gKjIynkOCbye6J_mPYIXjw40-XKpJL8yHP1udsgJj5WGS-SvZ9KHonKF4KqEp9keucLTTCC3PBm6AQfhkiv-yJA_8HQCBbS5xOPwMETr1jueEayeYAkqJU21apR-scOZKJU39pMEe8BTZk_rjNkR5rGhqW1F3BFn-1RvTYCH3y8L9uzWfi_cy93QemeTuucsam6aE27ZcazT-WbD8L5L8nSCncdlggXhbnkX1j7tfYlQneZCyG1JoPXK6niNg1Bn_kyQDWFhhM3DkpFH-pf-PafwvV9n_xrwlw5OfxSLFtWzLpTNpQTZhJkX4pqiGuu8385RNYfpZH4fNIEKlFSf3xb6W9lwgT7N6FWBzx6OlsKzotmv0ZdwgcmrOm5iGyGHTBcjLt6q0GXwkhBUuypeKri-ZKlmLmZgS72oxLyptUAe4CiQ6ldYj6eoRYE5kvPkfUtX-jIMJvRmM1H_tI-7QYKaC0xXC0kf73CjdQ8s_RZetYkgO0DhybqU78gKDBRBVuk25gTUVuWuauLXUhy6lF6I2T1RguPLaweCHHrrow_ah8r9ou9V-bryJwWXB9IbxIMi5j6oTuNTTvlebq6AYhirnCqM7EYWDEjngGdhauGeF0sxG4LM6EvIIqdKAac6waQsrlFU97n_C8BM";

  std::string encoded, decoded;
  EXPECT_TRUE(Base64WEncode(input, &encoded));
  EXPECT_EQ(b64w_random_bytes_encoded, encoded);

  EXPECT_TRUE(Base64WDecode(encoded, &decoded));
  EXPECT_EQ(input, decoded);
}

TEST(Base64WTest, Decode) {
  std::string b64w_encoded_no_padding = "ADYufZXrex-m4jN-_3rkB06rEZN4GgMl_zsCW_WGZuf4DsKApY3-kiwnYCTjO7igMqLuDWh2qx2kiTVwBsPgUSkLzJXoLmAPswVe6-RWV-lQRFkjUhJqAyC3Qpjl0PYtaFwSf4oj_bv-ixzOTddD1e_KsRNKQG3qspWKkRlh3pk46ZDTg9eb1j7xWPf_2E40hmt3ZmOggG4OJFka6DZKFVWgolw755uvIHuF6E5IuVPnFeuColYKZqdJxyQTrrSRBDoL9iwj5PSojMQxy9pqQrQsQovGaHco7wftEUika5ySJmwSjClpaXlQcG97_Y2VTwsvIHfcWtbnU5g3G0JKFzE";

  std::string b64w_encoded = "ADYufZXrex-m4jN-_3rkB06rEZN4GgMl_zsCW_WGZuf4DsKApY3-kiwnYCTjO7igMqLuDWh2qx2kiTVwBsPgUSkLzJXoLmAPswVe6-RWV-lQRFkjUhJqAyC3Qpjl0PYtaFwSf4oj_bv-ixzOTddD1e_KsRNKQG3qspWKkRlh3pk46ZDTg9eb1j7xWPf_2E40hmt3ZmOggG4OJFka6DZKFVWgolw755uvIHuF6E5IuVPnFeuColYKZqdJxyQTrrSRBDoL9iwj5PSojMQxy9pqQrQsQovGaHco7wftEUika5ySJmwSjClpaXlQcG97_Y2VTwsvIHfcWtbnU5g3G0JKFzE==";

  std::string b64w_encoded_ws = "ADYufZXrex-m4jN-_3rkB06rEZN4GgMl_zsCW_WGZuf4DsKApY3-kiwnYCTjO7igMqLuDWh2qx2kiTVwBsPgUSkLzJXoLmAPswVe6-RWV-lQRFkjUhJqAyC3Qpjl0PYtaFwSf4oj_bv-ixzOTddD1e_KsRNKQG3qspWKkRlh3pk46ZDTg9eb1j7xWPf_2E40hmt3ZmOggG4OJFka6DZKFVWgolw755uvIHuF6E5IuVPnFeuColYKZqdJxyQTrrSRBDoL9iwj5PSojMQxy9pqQrQsQovGaHco7wftEUika5ySJmwSjClpaXlQcG97_Y2VTwsvIHfcWtbnU5g3G0JKFzE==";

  std::string decoded;
  EXPECT_TRUE(Base64WDecode(b64w_encoded_no_padding, &decoded));
  EXPECT_TRUE(Base64WDecode(b64w_encoded, &decoded));
  EXPECT_TRUE(Base64WDecode(b64w_encoded_ws, &decoded));
}
