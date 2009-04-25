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
#ifndef KEYCZAR_OPENSSL_RSA_H_
#define KEYCZAR_OPENSSL_RSA_H_

#include <openssl/rsa.h>
#include <string>

#include "base/basictypes.h"
#include "base/scoped_ptr.h"
#include "testing/gtest/include/gtest/gtest_prod.h"

#include "keyczar/openssl/util.h"
#include "keyczar/rsa_impl.h"

namespace keyczar {

namespace openssl {

// OpenSSL concrete implementation.
class RSAOpenSSL : public RSAImpl {
 public:
  RSAOpenSSL(RSA* key, bool private_key)
      : key_(key), private_key_(private_key) {}

  virtual ~RSAOpenSSL() {}

  // Builds a concrete RSA implementation object from |key| and returns the
  // result. The caller takes ownership over the returned object.
  static RSAOpenSSL* Create(const RSAIntermediateKey& key, bool private_key);

  // Builds a concrete RSA implementation object from a new generated key of
  // length |size| and returns the result to the caller who takes ownership
  // over the returned instance. The value of |size| is expressed in bits.
  static RSAOpenSSL* GenerateKey(int size);

  virtual bool GetAttributes(RSAIntermediateKey* key);

  virtual bool GetPublicAttributes(RSAIntermediateKey* key);

  bool WriteKeyToPEMFile(const std::string& path);

  virtual bool Sign(const std::string& message_digest,
                    std::string* signature) const;

  virtual bool Verify(const std::string& message_digest,
                      const std::string& signature) const;

  virtual bool Encrypt(const std::string& data, std::string* encrypted) const;

  virtual bool Decrypt(const std::string& encrypted, std::string* data) const;

  bool Equals(const RSAOpenSSL& rhs) const;

  bool private_key() const { return private_key_; }

  const RSA* key() const { return key_.get(); }

 private:
  FRIEND_TEST(RSAOpenSSL, CreateKeyAndCompare);

  typedef scoped_ptr_malloc<
      RSA, openssl::OSSLDestroyer<RSA, RSA_free> > ScopedRSAKey;

  ScopedRSAKey key_;

  bool private_key_;

  DISALLOW_COPY_AND_ASSIGN(RSAOpenSSL);
};

}  // namespace openssl

}  // namespace keyczar

#endif  // KEYCZAR_OPENSSL_RSA_H_
