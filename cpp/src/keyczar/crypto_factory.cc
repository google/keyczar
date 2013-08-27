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
#include <keyczar/crypto_factory.h>

#include <keyczar/base/logging.h>
#include <keyczar/cipher_mode.h>
#include <keyczar/openssl/aes.h>
#include <keyczar/openssl/dsa.h>
#include <keyczar/openssl/ecdsa.h>
#include <keyczar/openssl/hmac.h>
#include <keyczar/openssl/message_digest.h>
#include <keyczar/openssl/pbe.h>
#include <keyczar/openssl/rand.h>
#include <keyczar/openssl/rsa.h>

namespace keyczar {

RandImpl* CryptoFactory::Rand() {
  static openssl::RandOpenSSL rand;
  if (!rand.is_initialized())
    CHECK(rand.Init());
  return &rand;
}

// static
MessageDigestImpl* CryptoFactory::SHA1() {
  return new openssl::MessageDigestOpenSSL(MessageDigestImpl::SHA1);
}

// static
MessageDigestImpl* CryptoFactory::SHA224() {
  return new openssl::MessageDigestOpenSSL(MessageDigestImpl::SHA1);
}

// static
MessageDigestImpl* CryptoFactory::SHA256() {
  return new openssl::MessageDigestOpenSSL(MessageDigestImpl::SHA256);
}

// static
MessageDigestImpl* CryptoFactory::SHA384() {
  return new openssl::MessageDigestOpenSSL(MessageDigestImpl::SHA384);
}

// static
MessageDigestImpl* CryptoFactory::SHA512() {
  return new openssl::MessageDigestOpenSSL(MessageDigestImpl::SHA512);
}

// static
MessageDigestImpl* CryptoFactory::SHA(int size) {
  switch (size) {
    case 160:
      return CryptoFactory::SHA1();
    case 224:
      return CryptoFactory::SHA224();
    case 256:
      return CryptoFactory::SHA256();
    case 384:
      return CryptoFactory::SHA384();
    case 512:
      return CryptoFactory::SHA512();
    default:
      NOTREACHED();
  }
  return NULL;
}

// static
MessageDigestImpl* CryptoFactory::SHAFromFFCIFCSize(int size) {
#ifdef COMPAT_KEYCZAR_06B
  return CryptoFactory::SHA1();
#else
  // These choices follow the recommendations made by NIST in document
  // SP800-57 part1 (Recommendation for Key Management) pages 63-64.
  switch (size) {
    case 1024:
      return CryptoFactory::SHA1();
    case 2048:
      return CryptoFactory::SHA224();
    case 3072:
      return CryptoFactory::SHA256();
    case 4096:
      return CryptoFactory::SHA512();
    default:
      NOTREACHED();
  }
  return NULL;
#endif
}

// static
MessageDigestImpl* CryptoFactory::SHAFromECCSize(int size) {
  // These choices follow the recommendations made by NIST in document
  // SP800-57 part1 (Recommendation for Key Management) pages 63-64 and
  // the compatibility defined under section 4 of RFC5480.
  switch (size) {
    case 192:
    case 224:
    case 256:
      return CryptoFactory::SHA256();
    case 384:
      return CryptoFactory::SHA384();
    default:
      NOTREACHED();
  }
  return NULL;
}

// static
AESImpl* CryptoFactory::GenerateAES(CipherMode::Type cipher_mode,
                                    int size) {
  return openssl::AESOpenSSL::GenerateKey(cipher_mode, size);
}

// static
AESImpl* CryptoFactory::CreateAES(CipherMode::Type cipher_mode,
                                  const std::string& key) {
  return openssl::AESOpenSSL::Create(cipher_mode, key);
}

// static
HMACImpl* CryptoFactory::GenerateHMAC(int size) {
#ifdef COMPAT_KEYCZAR_06B
  switch (size) {
    case 160:
      return openssl::HMACOpenSSL::GenerateKey(HMACImpl::SHA1, 256);
    default:
      NOTREACHED();
  }
  return NULL;
#else
  // The key length will be equal to the algorithm output's length |size|.
  // The RFC2104 says:
  //    The key for HMAC can be of any length (keys longer than B bytes are
  //    first hashed using H).  However, less than L bytes is strongly
  //    discouraged as it would decrease the security strength of the
  //    function.  Keys longer than L bytes are acceptable but the extra
  //    length would not significantly increase the function strength. (A
  //    longer key may be advisable if the randomness of the key is
  //    considered weak.)
  //
  // If a modification is made here, the function GetDigestNameFromHMACKeySize
  // (hmac_key.cc) would require to be updated accordingly.
  switch (size) {
    case 160:
      return openssl::HMACOpenSSL::GenerateKey(HMACImpl::SHA1, size);
    case 224:
      return openssl::HMACOpenSSL::GenerateKey(HMACImpl::SHA224, size);
    case 256:
      return openssl::HMACOpenSSL::GenerateKey(HMACImpl::SHA256, size);
    case 384:
      return openssl::HMACOpenSSL::GenerateKey(HMACImpl::SHA384, size);
    case 512:
      return openssl::HMACOpenSSL::GenerateKey(HMACImpl::SHA512, size);
    default:
      NOTREACHED();
  }
  return NULL;
#endif
}

// static
HMACImpl* CryptoFactory::CreateHMAC(const std::string& key) {
#ifdef COMPAT_KEYCZAR_06B
  return openssl::HMACOpenSSL::Create(HMACImpl::SHA1, key);
#else
  int size = key.length() * 8;

  // See comment above.
  switch (size) {
    case 160:
      return openssl::HMACOpenSSL::Create(HMACImpl::SHA1, key);
    case 224:
      return openssl::HMACOpenSSL::Create(HMACImpl::SHA224, key);
    case 256:
      return openssl::HMACOpenSSL::Create(HMACImpl::SHA256, key);
    case 384:
      return openssl::HMACOpenSSL::Create(HMACImpl::SHA384, key);
    case 512:
      return openssl::HMACOpenSSL::Create(HMACImpl::SHA512, key);
    default:
      NOTREACHED();
  }
  return NULL;
#endif
}

// static
PBEImpl* CryptoFactory::CreateNewPBE(const std::string& password) {
  const int iteration_count = 4096;
  const PBEImpl::CipherAlgorithm cipher_algorithm = PBEImpl::AES128;

  // Try to instanciate with use of hmac-sha256 but may not be supported
  // so in this case fall back on hmac-sha1.
  if (!openssl::PBEOpenSSL::HasPRFHMACSHA256())
    return openssl::PBEOpenSSL::Create(cipher_algorithm, PBEImpl::HMAC_SHA1,
                                       iteration_count, password);
  return openssl::PBEOpenSSL::Create(cipher_algorithm,
                                     PBEImpl::HMAC_SHA256,
                                     iteration_count, password);
}

// static
PBEImpl* CryptoFactory::CreatePBE(PBEImpl::CipherAlgorithm cipher_algorithm,
                                  PBEImpl::HMACAlgorithm hmac_algorithm,
                                  int iteration_count,
                                  const std::string& password) {
  return openssl::PBEOpenSSL::Create(cipher_algorithm, hmac_algorithm,
                                     iteration_count, password);
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
RSAImpl* CryptoFactory::CreatePrivateRSAFromPEMPrivateKey(
    const std::string& filename, const std::string* passphrase) {
  return openssl::RSAOpenSSL::CreateFromPEMPrivateKey(filename, passphrase);
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
DSAImpl* CryptoFactory::CreatePrivateDSAFromPEMPrivateKey(
    const std::string& filename, const std::string* passphrase) {
  return openssl::DSAOpenSSL::CreateFromPEMPrivateKey(filename, passphrase);
}

// static
DSAImpl* CryptoFactory::CreatePublicDSA(
    const DSAImpl::DSAIntermediateKey& key) {
  return openssl::DSAOpenSSL::Create(key, false);
}

// static
ECDSAImpl* CryptoFactory::GeneratePrivateECDSA(ECDSAImpl::Curve curve) {
  return openssl::ECDSAOpenSSL::GenerateKey(curve);
}

// static
ECDSAImpl* CryptoFactory::CreatePrivateECDSA(
    const ECDSAImpl::ECDSAIntermediateKey& key) {
  return openssl::ECDSAOpenSSL::Create(key, true);
}

// static
ECDSAImpl* CryptoFactory::CreatePrivateECDSAFromPEMPrivateKey(
    const std::string& filename, const std::string* passphrase) {
  return openssl::ECDSAOpenSSL::CreateFromPEMPrivateKey(filename, passphrase);
}

// static
ECDSAImpl* CryptoFactory::CreatePublicECDSA(
    const ECDSAImpl::ECDSAIntermediateKey& key) {
  return openssl::ECDSAOpenSSL::Create(key, false);
}

}  // namespace keyczar
