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
#include "keyczar/openssl/hmac.h"

#include "base/logging.h"

#include "keyczar/crypto_factory.h"
#include "keyczar/rand_impl.h"

namespace keyczar {

namespace openssl {

HMACOpenSSL::HMACOpenSSL(const EVP_MD* (*evp_md)(), const std::string& key)
    : evp_md_(evp_md), key_(key), engine_(NULL) {
  // Initializes the hmac context.
  HMAC_CTX_init(&context_);
}

HMACOpenSSL::~HMACOpenSSL() {
  HMAC_CTX_cleanup(&context_);
}

// static
HMACOpenSSL* HMACOpenSSL::Create(DigestAlgorithm digest_algorithm,
                                 const std::string& key) {
  // Currently only SHA1 is supported.
  switch (digest_algorithm) {
    case HMACImpl::SHA1:
      return new HMACOpenSSL(EVP_sha1, key);
    default:
      NOTREACHED();
  }
  return NULL;
}

// static
HMACOpenSSL* HMACOpenSSL::GenerateKey(DigestAlgorithm digest_algorithm,
                                      int size) {
  RandImpl* rand_impl = CryptoFactory::Rand();
  if (rand_impl == NULL)
    return NULL;

  std::string key;
  if (!rand_impl->RandBytes(size / 8, &key))
    return NULL;
  DCHECK(static_cast<int>(key.length()) == size / 8);

  return HMACOpenSSL::Create(digest_algorithm, key);
}

bool HMACOpenSSL::Init() {
  if (evp_md_ == NULL)
    return false;

  HMAC_Init_ex(&context_,
               reinterpret_cast<unsigned char*>(
                   const_cast<char*>(key_.data())),
               key_.length(),
               evp_md_(),
               engine_);
  return true;
}

bool HMACOpenSSL::Update(const std::string& data) {
  HMAC_Update(&context_,
              reinterpret_cast<unsigned char*>(
                  const_cast<char*>(data.data())),
              data.length());
  return true;
}

bool HMACOpenSSL::Final(std::string* digest) {
  unsigned char md_buffer[EVP_MAX_MD_SIZE];
  uint32 md_len = 0;

  HMAC_Final(&context_, md_buffer, &md_len);
  digest->assign(reinterpret_cast<char*>(md_buffer), md_len);
  return true;
}

}  // namespace openssl

}  // namespace keyczar
