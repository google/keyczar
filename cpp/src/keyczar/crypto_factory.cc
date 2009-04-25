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
#include "keyczar/crypto_factory.h"

#include "base/logging.h"

#include "keyczar/cipher_mode.h"
#include "keyczar/openssl/aes.h"
#include "keyczar/openssl/dsa.h"
#include "keyczar/openssl/hmac.h"
#include "keyczar/openssl/message_digest.h"
#include "keyczar/openssl/rand.h"
#include "keyczar/openssl/rsa.h"

namespace keyczar {

RandImpl* CryptoFactory::Rand() {
  static openssl::RandOpenSSL rand;
  if (!rand.is_initialized())
    DCHECK(rand.Init());
  return &rand;
}

// static
MessageDigestImpl* CryptoFactory::SHA1() {
  static openssl::MessageDigestOpenSSL md(MessageDigestImpl::SHA1);
  return &md;
}

// static
AESImpl* CryptoFactory::GenerateAES(const CipherMode& cipher_mode,
                                    int size) {
  return openssl::AESOpenSSL::GenerateKey(cipher_mode, size);
}

// static
AESImpl* CryptoFactory::CreateAES(const CipherMode& cipher_mode,
                                  const std::string& key) {
  return openssl::AESOpenSSL::Create(cipher_mode, key);
}

// static
HMACImpl* CryptoFactory::GenerateHMACSHA1(int size) {
  return openssl::HMACOpenSSL::GenerateKey(HMACImpl::SHA1, size);
}

// static
HMACImpl* CryptoFactory::CreateHMACSHA1(const std::string& key) {
  return openssl::HMACOpenSSL::Create(HMACImpl::SHA1, key);
}

// static
RSAImpl* CryptoFactory::GeneratePrivateRSA(int size) {
  return openssl::RSAOpenSSL::GenerateKey(size);
}

// static
RSAImpl* CryptoFactory::CreatePrivateRSA(
    const RSAImpl::RSAIntermediateKey& key) {
  return openssl::RSAOpenSSL::Create(key, true);
}

// static
RSAImpl* CryptoFactory::CreatePublicRSA(
    const RSAImpl::RSAIntermediateKey& key) {
  return openssl::RSAOpenSSL::Create(key, false);
}

// static
DSAImpl* CryptoFactory::GeneratePrivateDSA(int size) {
  return openssl::DSAOpenSSL::GenerateKey(size);
}

// static
DSAImpl* CryptoFactory::CreatePrivateDSA(
    const DSAImpl::DSAIntermediateKey& key) {
  return openssl::DSAOpenSSL::Create(key, true);
}

// static
DSAImpl* CryptoFactory::CreatePublicDSA(
    const DSAImpl::DSAIntermediateKey& key) {
  return openssl::DSAOpenSSL::Create(key, false);
}

}  // namespace keyczar
