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

static const int kPasswordBufferSize = 1024;

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

EVP_PKEY* ReadPEMPrivateKeyFromFile(const std::string& filename,
                                    const std::string* passphrase) {
  ScopedBIO in(BIO_new_file(filename.c_str(), "r"));
  if (in.get() == NULL) {
    PrintOSSLErrors();
    return NULL;
  }

  // Needs ciphers and digests to be loaded.
  OpenSSL_add_all_algorithms();

  char* c_passphrase;
  if (passphrase != NULL) {
    c_passphrase = const_cast<char*>(passphrase->c_str());
  } else {
    c_passphrase = NULL;
  }
  ScopedEVPPKey evp_pkey;
  // The first NULL value means we are not implementing our own password
  // callback function but that we will rely on the default one instead.

  // TODO(dlundberg): For consistency in the UI a callback should probably
  // be supplied. This will only matter if a user doesn't specify there
  // needs to be a passphrase and the file actually requires one.
  evp_pkey.reset(PEM_read_bio_PrivateKey(in.get(), NULL, NULL, c_passphrase));

  // Removes the ciphers from the table.
  EVP_cleanup();

  return evp_pkey.release();
}

bool WritePEMPrivateKeyToFile(EVP_PKEY* key, const std::string& filename,
                              const std::string* passphrase) {
  ScopedBIO out(BIO_new_file(filename.c_str(), "w"));
  if (out.get() == NULL) {
    PrintOSSLErrors();
    return false;
  }

  // Needs ciphers and digests symbols.
  OpenSSL_add_all_algorithms();

  // Cipher used for key encryption.
  const EVP_CIPHER* cipher = EVP_aes_128_cbc();

  int result = 0;
  char* c_passphrase;
  if (passphrase != NULL) {
    c_passphrase = const_cast<char*>(passphrase->c_str());
  } else {
    c_passphrase = NULL;
  }
  // TODO(dlundberg): For consistency in the UI a callback should probably
  // be supplied. This will only matter if a user doesn't specify there
  // needs to be a passphrase and the file actually requires one.
  result = PEM_write_bio_PKCS8PrivateKey(
      out.get(), key, cipher, NULL, 0, NULL, c_passphrase);

  // Cleanup symbols table.
  EVP_cleanup();

  if (result != 1)
    return false;
  return true;
}

bool PromptPassword(const std::string& prompt, std::string* password) {
  // There is no password so prompt it interactively
  char password_buffer[kPasswordBufferSize + 1];
  if (EVP_read_pw_string(password_buffer, kPasswordBufferSize,
                         const_cast<char*>(prompt.c_str()), 0) != 0) {
    memset(password_buffer, 0, kPasswordBufferSize);
    PrintOSSLErrors();
    return false;
  }
  password_buffer[kPasswordBufferSize] = '\0';

  password = new std::string(password_buffer);
  memset(password_buffer, 0, kPasswordBufferSize);

  return true;
}

}  // namespace openssl

}  // namespace keyczar
