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
#ifndef KEYCZAR_CRYPTO_FACTORY_H_
#define KEYCZAR_CRYPTO_FACTORY_H_

#include <string>

#include "keyczar/aes_impl.h"
#include "keyczar/dsa_impl.h"
#include "keyczar/hmac_impl.h"
#include "keyczar/message_digest_impl.h"
#include "keyczar/rand_impl.h"
#include "keyczar/rsa_impl.h"

namespace keyczar {

class CipherMode;

// Factory for crypto implementation. Currently this class only builds OpenSSL
// objects.
class CryptoFactory {
 public:
  static RandImpl* Rand();

  static MessageDigestImpl* SHA1();

  static AESImpl* GenerateAES(const CipherMode& cipher_mode, int size);

  static AESImpl* CreateAES(const CipherMode& cipher_mode,
                            const std::string& key);

  static HMACImpl* GenerateHMACSHA1(int size);

  static HMACImpl* CreateHMACSHA1(const std::string& key);

  static RSAImpl* GeneratePrivateRSA(int size);

  static RSAImpl* CreatePrivateRSA(const RSAImpl::RSAIntermediateKey& key);

  static RSAImpl* CreatePublicRSA(const RSAImpl::RSAIntermediateKey& key);

  static DSAImpl* GeneratePrivateDSA(int size);

  static DSAImpl* CreatePrivateDSA(const DSAImpl::DSAIntermediateKey& key);

  static DSAImpl* CreatePublicDSA(const DSAImpl::DSAIntermediateKey& key);

 private:
  CryptoFactory() {}
};

}  // namespace keyczar

#endif  // KEYCZAR_CRYPTO_FACTORY_H_
