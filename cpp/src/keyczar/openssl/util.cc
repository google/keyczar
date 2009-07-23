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
#include <keyczar/openssl/util.h>

#include <openssl/pem.h>

#include <keyczar/base/file_util.h>

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

EVP_PKEY* ReadPEMKeyFromFile(const std::string& filename,
                             const std::string* passphrase) {
  FILE* src_file = file_util::OpenFile(filename, "r");
  if (src_file == NULL) {
    LOG(ERROR) << "Cannot open " << filename;
    return NULL;
  }

  // Ciphers table requires to be loaded for call to EVP_get_cipher_byname().
  // Wich is called by the next function.
  OpenSSL_add_all_ciphers();

  EVP_PKEY* evp_pkey = NULL;
  // The first NULL value means we are not implementing our own password
  // callback function but that we will rely on the default one instead.
  if (passphrase != NULL)
    evp_pkey = PEM_read_PrivateKey(src_file, NULL, NULL,
                                   const_cast<char*>(passphrase->c_str()));
  else
    evp_pkey = PEM_read_PrivateKey(src_file, NULL, NULL, NULL);

  // Removes the ciphers from the table.
  EVP_cleanup();

  return evp_pkey;
}

}  // namespace openssl

}  // namespace keyczar
