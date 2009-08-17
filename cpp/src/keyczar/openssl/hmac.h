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
#ifndef KEYCZAR_OPENSSL_HMAC_H_
#define KEYCZAR_OPENSSL_HMAC_H_

#include <openssl/hmac.h>

#include <string>

#include <keyczar/base/basictypes.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/stl_util-inl.h>
#include <keyczar/hmac_impl.h>

namespace keyczar {

namespace openssl {

class HMACOpenSSL : public HMACImpl {
 public:
  virtual ~HMACOpenSSL();

  static HMACOpenSSL* Create(DigestAlgorithm digest_algorithm,
                             const std::string& key);

  // |size| is expressed in bits.
  static HMACOpenSSL* GenerateKey(DigestAlgorithm digest_algorithm, int size);

  virtual bool Init();

  virtual bool Update(const std::string& data);

  virtual bool Final(std::string* digest);

  virtual const std::string& GetKey() const { return *key_; }

 private:
  // The caller must insures that the length of |key| is acceptable.
  HMACOpenSSL(const EVP_MD* (*evp_md)(), const std::string& key);

  const EVP_MD* (*evp_md_)();

  // The secret key.
  const base::ScopedSafeString key_;

  // The caller keeps ownership over the engine. Note: the use of a true engine
  // is currently not supported.
  ENGINE* engine_;

  // Openssl hmac context. Must be appropriately initialized before its
  // first use, see the constructor.
  HMAC_CTX context_;

  DISALLOW_COPY_AND_ASSIGN(HMACOpenSSL);
};

}  // namespace openssl

}  // namespace keyczar

#endif  // KEYCZAR_OPENSSL_HMAC_H_
