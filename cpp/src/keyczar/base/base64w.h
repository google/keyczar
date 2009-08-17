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
#ifndef KEYCZAR_BASE_BASE64W_H_
#define KEYCZAR_BASE_BASE64W_H_

#include <string>

namespace keyczar {
namespace base {

// Encodes the input string in web safe base64. Returns true if successful and
// false otherwise. The output string is only modified if successful. The
// outputted string will be emitted without padding nor trailing nul bytes.
bool Base64WEncode(const std::string& input, std::string* output);

// Decodes the web safe base64 input string. Returns true if successful and
// false otherwise. The output string is only modified if successful. The
// input string can optionnaly be padded with character '=', the padding will
// be removed before decoding it. Likewise trailing whitespaces are removed
// from input string.
bool Base64WDecode(const std::string& input, std::string* output);

}  // namespace base
}  // namespace keyczar

#endif  // KEYCZAR_BASE_BASE64W_H_
