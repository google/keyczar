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
#ifndef KEYCZAR_OPENSSL_DSA_H_
#define KEYCZAR_OPENSSL_DSA_H_

#include <openssl/dsa.h>

#include <string>

#include <keyczar/base/basictypes.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/dsa_impl.h>
#include <keyczar/openssl/util.h>

namespace keyczar {

namespace openssl {

// OpenSSL concrete implementation.
class DSAOpenSSL : public DSAImpl {
 public:
  virtual ~DSAOpenSSL() {}

  // Builds a DSAOpenSSL object from |key|. |key| must be correctly formed
  // and initialized. The caller takes ownership over the returned object.
  static DSAOpenSSL* Create(const DSAIntermediateKey& key, bool private_key);

  // Builds a DSAOpenSSL object from a new generated key of size |size|. The
  // value of |size| is expressed in bits. The caller takes ownership over
  // the returned instance.
  static DSAOpenSSL* GenerateKey(int size);

  // Builds an DSAOpenSSL object from a PEM private key stored at |filename|.
  // |passphrase| is an optional passphrase. Its value is NULL if no
  // passphrase is expected or if it should be prompted interactively at
  // execution. The caller takes ownership over the returned object.
  // It can handle PEM format keys as well as PKCS8 format keys.
  static DSAOpenSSL* CreateFromPEMPrivateKey(const std::string& filename,
                                             const std::string* passphrase);

  // Exports this key encrypted with |passphrase| to |filename|. The format
  // used is PKCS8 and the key is encrypted with PBE algorithm as defined in
  // PKCS5 v2.0, the associated cipher used is AES. If |passphrase| is NULL
  // a callback function will be called to prompt a passphrase at execution.
  virtual bool ExportPrivateKey(const std::string& filename,
                                const std::string* passphrase) const;

  virtual bool GetAttributes(DSAIntermediateKey* key);

  virtual bool GetPublicAttributes(DSAIntermediateKey* key);

  virtual bool Sign(const std::string& message_digest,
                    std::string* signature) const;

  virtual bool Verify(const std::string& message_digest,
                      const std::string& signature) const;

  virtual int Size() const;

  bool Equals(const DSAOpenSSL& rhs) const;

  bool private_key() const { return private_key_; }

  const DSA* key() const { return key_.get(); }

 private:
  FRIEND_TEST(DSAOpenSSL, CreateKeyAndCompare);

  // DSA_free internally calls BN_clear_free() to clear the DSA fields
  // with OPENSSL_cleanse() before freeing the memory.
  typedef scoped_ptr_malloc<
      DSA, openssl::OSSLDestroyer<DSA, DSA_free> > ScopedDSAKey;

  DSAOpenSSL(DSA* key, bool private_key)
      : key_(key), private_key_(private_key) {}

  const ScopedDSAKey key_;

  bool private_key_;

  DISALLOW_COPY_AND_ASSIGN(DSAOpenSSL);
};

}  // namespace openssl

}  // namespace keyczar

#endif  // KEYCZAR_OPENSSL_DSA_H_
