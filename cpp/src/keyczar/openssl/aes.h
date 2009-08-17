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

#include <keyczar/aes_impl.h>
#include <keyczar/base/basictypes.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/stl_util-inl.h>
#include <keyczar/cipher_mode.h>
#include <keyczar/openssl/util.h>

namespace keyczar {

namespace openssl {

// OpenSSL concrete implementation.
class AESOpenSSL : public AESImpl {
 public:
  virtual ~AESOpenSSL();

  // Instantiates a concrete AES implementation object from its |cipher_mode|
  // and its length of key deduced from the length of |key|. Currently only
  // the operating mode CBC is supported. The caller takes  ownership over the
  // returned object.
  static AESOpenSSL* Create(CipherMode::Type cipher_mode,
                            const std::string& key);

  // The value of |size| is expressed in bits.
  static AESOpenSSL* GenerateKey(CipherMode::Type cipher_mode, int size);

  // Atomically encrypts |plaintext| and put the cipher text and the
  // corresponding IV respectively into |ciphertext| and |iv|. Internally
  // an IV is generated at random before encryption. This method successively
  // calls EncryptInit, EncryptUpdate, EncryptFinal and EncryptContextCleanup.
  // If this function fails it returns false.
  virtual bool Encrypt(const std::string& plaintext, std::string* ciphertext,
                       std::string* iv) const;

  // Initializes encryption context. When the encryption is accomplished through
  // this set of methods (EncryptInit, EncryptUpdate, EncryptFinal) it is not
  // possible to encrypt two differents plaintexts at same time because the
  // Encrypt* methods share the same context. Therefore one must be sure to not
  // interleave multiple encryptions. However one encryption can be interleaved
  // with one decryption because encryption and decryption use two separate
  // contexts. This method generates an IV and returns it as |iv|.
  virtual bool EncryptInit(std::string* iv) const;

  // Encrypts |plaintext| and appends the result into |ciphertext|. This method
  // can be called multiple times to encrypt small plaintexts chunks into
  // |ciphertext|. Therefore |ciphertext| must be empty during the first call to
  // this method.
  virtual bool EncryptUpdate(const std::string& plaintext,
                             std::string* ciphertext) const;

  // Finalizes encryption, the last block is written to |ciphertext|. This
  // method should be called after EncryptUpdate.
  virtual bool EncryptFinal(std::string* ciphertext) const;

  // Atomically decrypts |ciphertext| and put the corresponding plaintext inside
  // |plaintext|. |iv| must be provided. If this function fails it returns
  // false. This method internally successively calls DecryptInit,
  // DecryptUpdate, DecryptFinal and DecryptContextCleanup.
  virtual bool Decrypt(const std::string& iv, const std::string& ciphertext,
                       std::string* plaintext) const;

  // Initializes decryption context. When the decryption is accomplished through
  // this set of methods (DecryptInit, DecryptUpdate, DecryptFinal) it is not
  // possible to decrypt two differents plaintexts at same time because the
  // Decrypt* methods share the same context. Therefore one must be sure to not
  // interleave multiple decryptions. However one decryption can be interleaved
  // with one encryption because encryption and decryption use two separate
  // contexts.
  virtual bool DecryptInit(const std::string& iv) const;

  // Decrypts |ciphertext| and appends the result into |plaintext|. This method
  // can be called multiple times to decrypt small ciphertexts chunks into
  // |plaintext|. Therefore |plaintext| must be empty during the first call to
  // this method.
  virtual bool DecryptUpdate(const std::string& ciphertext,
                             std::string* plaintext) const;

  // Finalizes decryption, the last block is written to |plaintext|. This
  // method should be called after DecryptUpdate.
  virtual bool DecryptFinal(std::string* plaintext) const;

  virtual const std::string& GetKey() const { return *key_; }

  // Returns the size of the secret key this number can be used as length
  // of the initialization vector. The return value is expressed in bytes.
  virtual int GetKeySize() const;

 private:
  // Scoped cipher context, function EVP_CIPHER_CTX_free() will be called
  // on object destruction.
  typedef scoped_ptr_malloc<
      EVP_CIPHER_CTX, openssl::OSSLDestroyer<EVP_CIPHER_CTX,
      EVP_CIPHER_CTX_free> > ScopedCipherCtx;

  // No need to explicitly call EVP_CIPHER_CTX_init because this function is
  // already called inside the factory function EVP_CIPHER_CTX_new used for
  // initializing the context.
  AESOpenSSL(const EVP_CIPHER* (*evp_cipher)(), const std::string& key);

  // This method securely erase the current encryption context. It should be
  // called after each completed encryption (that the encryption succeeded or
  // failed).
  virtual void EncryptContextCleanup() const;

  // This method securely erase the current decryption context. It should be
  // called after each completed decryption (that the decryption succeeded or
  // failed).
  virtual void DecryptContextCleanup() const;

  bool CipherInit(const std::string& iv, bool encrypt,
                  EVP_CIPHER_CTX* context) const;

  bool CipherUpdate(const std::string& in_data, std::string* out_data,
                    EVP_CIPHER_CTX* context) const;

  bool CipherFinal(std::string* out_data, EVP_CIPHER_CTX* context) const;

  // TODO(seb): Currently EVP_CIPHER is obtained each time by calling this
  // function because I'm not sure how the pointer would be released in the
  // case where EVP_CipherInit_ex() were never called.
  const EVP_CIPHER* (*evp_cipher_)();

  // This is the secret key.
  const base::ScopedSafeString key_;

  // Encryption context used by encryption methods.
  ScopedCipherCtx encryption_context_;

  // Decryption context used by decryption methods.
  ScopedCipherCtx decryption_context_;

  // The caller keeps ownership over the engine. Note: the use of a true engine
  // is currently not supported.
  ENGINE* engine_;

  DISALLOW_COPY_AND_ASSIGN(AESOpenSSL);
};

}  // namespace openssl

}  // namespace keyczar

#endif  // KEYCZAR_OPENSSL_AES_H_
