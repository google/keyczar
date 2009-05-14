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
#include "keyczar/openssl/aes.h"

#include "base/logging.h"

#include "keyczar/cipher_mode.h"
#include "keyczar/crypto_factory.h"
#include "keyczar/rand_impl.h"

namespace keyczar {

namespace openssl {

AESOpenSSL::AESOpenSSL(const EVP_CIPHER* (*evp_cipher)(),
                       const std::string& key)
    : evp_cipher_(evp_cipher), key_(key), context_(EVP_CIPHER_CTX_new()),
      engine_(NULL) {
  CHECK(evp_cipher()->key_len == static_cast<int>(key.length()));
}

// static
AESOpenSSL* AESOpenSSL::Create(const CipherMode& cipher_mode,
                               const std::string& key) {
  // Only CBC mode is currently supported
  if (cipher_mode.type() != CipherMode::CBC) {
    NOTREACHED();
    return NULL;
  }

  int key_length = key.length() * 8;
  switch (key_length) {
    case 128:
      return new AESOpenSSL(EVP_aes_128_cbc, key);
    case 192:
      return new AESOpenSSL(EVP_aes_192_cbc, key);
    case 256:
      return new AESOpenSSL(EVP_aes_256_cbc, key);
    default:
      NOTREACHED();
  }
  return NULL;
}

// static
AESOpenSSL* AESOpenSSL::GenerateKey(const CipherMode& cipher_mode,
                                    int size) {
  RandImpl* rand_impl = CryptoFactory::Rand();
  if (rand_impl == NULL)
    return NULL;

  std::string key;
  if (!rand_impl->RandBytes(size / 8, &key))
    return NULL;
  DCHECK(static_cast<int>(key.length()) == size / 8);

  return AESOpenSSL::Create(cipher_mode, key);
}

bool AESOpenSSL::Encrypt(const std::string* iv, const std::string& data,
                         std::string* encrypted) const {
  return EVPCipher(iv, data, encrypted, 1);
}

bool AESOpenSSL::Decrypt(const std::string* iv, const std::string& encrypted,
                         std::string* data) const {
  return EVPCipher(iv, encrypted, data, 0);
}

bool AESOpenSSL::EVPCipher(const std::string* iv, const std::string& in_data,
                           std::string* out_data, int encrypt) const {
  if (encrypt != 1 && encrypt != 0)
    return false;

  if (evp_cipher_ == NULL)
    return false;

  // Checks if an iv is needed and in this case if it is provided. If iv is
  // required its length must be at least equal to block size.
  if ((evp_cipher_()->iv_len == 0 && iv != NULL) ||
      (evp_cipher_()->iv_len > 0 &&
       (iv == NULL ||
        static_cast<int>(iv->length()) < evp_cipher_()->block_size)))
    return false;

  if (context_.get() == NULL)
    return false;

  int ret_val = 0;
  if (iv == NULL)
    ret_val = EVP_CipherInit_ex(context_.get(),
                             evp_cipher_(),
                             engine_,
                             reinterpret_cast<unsigned char*>(
                                 const_cast<char*>(key_.data())),
                             NULL,
                             encrypt);
  else
    ret_val = EVP_CipherInit_ex(context_.get(),
                             evp_cipher_(),
                             engine_,
                             reinterpret_cast<unsigned char*>(
                                 const_cast<char*>(key_.data())),
                             reinterpret_cast<unsigned char*>(
                                 const_cast<char*>(iv->data())),
                             encrypt);
  if (!ret_val)
    return false;

  scoped_ptr_malloc<unsigned char> out_buffer;
  out_buffer.reset(reinterpret_cast<unsigned char*>(
                       malloc(in_data.length() + evp_cipher_()->block_size)));
  if (out_buffer.get() == NULL)
    return false;

  int update_length = 0;
  ret_val = EVP_CipherUpdate(context_.get(),
                             out_buffer.get(),
                             &update_length,
                             reinterpret_cast<unsigned char*>(
                                 const_cast<char*>(in_data.data())),
                             in_data.length());
  if (!ret_val)
    return false;

  int final_length = 0;
  ret_val = EVP_CipherFinal_ex(context_.get(),
                               out_buffer.get() + update_length,
                               &final_length);
  if (!ret_val)
    return false;

  out_data->assign(reinterpret_cast<char*>(out_buffer.get()),
                   update_length + final_length);
  return true;
}

int AESOpenSSL::GetKeySize() const {
  int key_length = static_cast<int>(key_.length());
  DCHECK(evp_cipher_ && key_length >= evp_cipher_()->iv_len);
  return key_length;
}

}  // namespace openssl

}  // namespace keyczar
