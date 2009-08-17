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

#include <keyczar/aes_impl.h>
#include <keyczar/cipher_mode.h>
#include <keyczar/dsa_impl.h>
#include <keyczar/ecdsa_impl.h>
#include <keyczar/hmac_impl.h>
#include <keyczar/message_digest_impl.h>
#include <keyczar/pbe_impl.h>
#include <keyczar/rand_impl.h>
#include <keyczar/rsa_impl.h>

namespace keyczar {

// Factory for crypto implementation. Currently this class only builds OpenSSL
// objects.
class CryptoFactory {
 public:
  static RandImpl* Rand();

  static MessageDigestImpl* SHA1();

  static MessageDigestImpl* SHA224();

  static MessageDigestImpl* SHA256();

  static MessageDigestImpl* SHA384();

  static MessageDigestImpl* SHA512();

  // Returns the appropriate SHA algorithm from its output |size| in bits.
  static MessageDigestImpl* SHA(int size);

  // Returns the SHA algorithm wich has a comparable security strength
  // than an RSA or DSA key of length |size|.
  static MessageDigestImpl* SHAFromFFCIFCSize(int size);

  // Returns the SHA algorithm wich has a comparable security strength
  // than an ECC key of length |size|.
  static MessageDigestImpl* SHAFromECCSize(int size);

  static AESImpl* GenerateAES(CipherMode::Type cipher_mode, int size);

  static AESImpl* CreateAES(CipherMode::Type cipher_mode,
                            const std::string& key);

  static HMACImpl* GenerateHMAC(int size);

  static HMACImpl* CreateHMAC(const std::string& key);

  static PBEImpl* CreateNewPBE(const std::string& password);

  static PBEImpl* CreatePBE(PBEImpl::CipherAlgorithm cipher_algorithm,
                            PBEImpl::HMACAlgorithm hmac_algorithm,
                            int iteration_count,
                            const std::string& password);

  static RSAImpl* GeneratePrivateRSA(int size);

  static RSAImpl* CreatePrivateRSA(const RSAImpl::RSAIntermediateKey& key);

  static RSAImpl* CreatePrivateRSAFromPEMPrivateKey(
      const std::string& filename, const std::string* passphrase);

  static RSAImpl* CreatePublicRSA(const RSAImpl::RSAIntermediateKey& key);

  static DSAImpl* GeneratePrivateDSA(int size);

  static DSAImpl* CreatePrivateDSAFromPEMPrivateKey(
      const std::string& filename, const std::string* passphrase);

  static DSAImpl* CreatePrivateDSA(const DSAImpl::DSAIntermediateKey& key);

  static DSAImpl* CreatePublicDSA(const DSAImpl::DSAIntermediateKey& key);

  static ECDSAImpl* GeneratePrivateECDSA(ECDSAImpl::Curve curve);

  static ECDSAImpl* CreatePrivateECDSAFromPEMPrivateKey(
      const std::string& filename, const std::string* passphrase);

  static ECDSAImpl* CreatePrivateECDSA(
      const ECDSAImpl::ECDSAIntermediateKey& key);

  static ECDSAImpl* CreatePublicECDSA(
      const ECDSAImpl::ECDSAIntermediateKey& key);

 private:
  CryptoFactory() {}
};

}  // namespace keyczar

#endif  // KEYCZAR_CRYPTO_FACTORY_H_
