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
#include "keyczar/openssl/util.h"

namespace keyczar {

namespace openssl {

void PrintOSSLErrors() {
  char error_buffer[1000];
  uint32 error_code = 0;

  ERR_load_crypto_strings();
  while ((error_code = ERR_get_error()) != 0) {
    ERR_error_string_n(error_code, error_buffer, 1000);
    LOG(ERROR) << error_buffer;
  }
  ERR_free_strings();
}

}  // namespace openssl

}  // namespace keyczar
