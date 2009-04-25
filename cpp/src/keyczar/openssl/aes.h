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
#ifndef KEYCZAR_OPENSSL_AES_H_
#define KEYCZAR_OPENSSL_AES_H_

#include <openssl/evp.h>
#include <string>

#include "base/basictypes.h"
#include "base/scoped_ptr.h"

#include "keyczar/openssl/util.h"
#include "keyczar/aes_impl.h"

namespace keyczar {

class CipherMode;

namespace openssl {

// OpenSSL concrete implementation.
class AESOpenSSL : public AESImpl {
 public:
  // No need to explicitly call EVP_CIPHER_CTX_init because this function is
  // already called inside the factory function EVP_CIPHER_CTX_new used for
  // initializing the context.
  AESOpenSSL(const EVP_CIPHER* (*evp_cipher)(), const std::string& key);

  virtual ~AESOpenSSL() {}

  // Instantiates a concrete AES implementation object from its |cipher_mode|
  // and its length of key deduced from the length of |key|. Currently only
  // the operating mode CBC is supported. The caller takes  ownership over the
  // returned object.
  static AESOpenSSL* Create(const CipherMode& cipher_mode,
                            const std::string& key);

  // The value of |size| is expressed in bits.
  static AESOpenSSL* GenerateKey(const CipherMode& cipher_mode, int size);

  // Encrypts |data| and put the cipher text inside |encrypted|. If needed
  // |iv| must be provided. If this function fails it returns false.
  virtual bool Encrypt(const std::string* iv, const std::string& data,
                       std::string* encrypted) const;

  // Decrypts |encrypted| data and put the plain text inside |data|. If needed
  // |iv| must be provided. If this function fails it returns false.
  virtual bool Decrypt(const std::string* iv, const std::string& encrypted,
                       std::string* data) const;

  virtual std::string GetKey() const { return key_; }

  // Returns the size of the secret key this number can be used as length
  // of the initialization vector. The return value is expressed in bytes.
  virtual int GetKeySize() const;

 private:
  // Scoped cipher context, function EVP_CIPHER_CTX_free() will be called
  // on object destruction.
  typedef scoped_ptr_malloc<
      EVP_CIPHER_CTX, openssl::OSSLDestroyer<EVP_CIPHER_CTX,
      EVP_CIPHER_CTX_free> > ScopedCipherCtx;

  bool EVPCipher(const std::string* iv, const std::string& in_data,
                 std::string* out_data, int encrypt) const;

  // TODO(seb): Currently EVP_CIPHER is obtained each time by calling this
  // function because I'm not sure how the pointer would be released in the
  // case where EVP_CipherInit_ex() were never called.
  const EVP_CIPHER* (*evp_cipher_)();

  // This is the secret key.
  std::string key_;

  // When this context will be released, EVP_CIPHER_CTX_cleanup() will
  // also automatically called. This context is used for both encryption
  // and decryption functions, this is not a problem because these functions
  // are executed atomically et do not have to maintain states.
  ScopedCipherCtx context_;

  // The caller keeps ownership over the engine. Note: the use of a true engine
  // is currently not supported.
  ENGINE* engine_;

  DISALLOW_COPY_AND_ASSIGN(AESOpenSSL);
};

}  // namespace openssl

}  // namespace keyczar

#endif  // KEYCZAR_OPENSSL_AES_H_
