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
#include <keyczar/base/modp/modp_b64w.h>

namespace keyczar {
namespace base {

bool Base64WEncode(const std::string& input, std::string* output) {
  if (output == NULL)
    return false;

  output->assign(modp::b64w_encode(input).c_str());
  if (output->empty())
    return false;
  return true;
}

bool Base64WDecode(const std::string& input, std::string* output) {
  if (output == NULL)
    return false;

  const std::string::size_type last_good_char = input.find_last_not_of("= ");

  output->assign(modp::b64w_decode(input.substr(0, last_good_char+1)));

  if (output->empty())
    return false;

  return true;
}

}  // namespace base
}  // namespace keyczar
