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
#ifndef KEYCZAR_AES_IMPL_H_
#define KEYCZAR_AES_IMPL_H_

#include <string>

#include <keyczar/base/basictypes.h>

namespace keyczar {

// Cryptographic AES interface.
class AESImpl {
 public:
  AESImpl() {}
  virtual ~AESImpl() {}

  // Atomically encrypts |plaintext| and put the resulting ciphertext and
  // corresponding IV respectively into |ciphertext| and |iv|. Internally
  // an IV is generated at random before encryption. This method successively
  // calls EncryptInit, EncryptUpdate, EncryptFinal and EncryptContextCleanup.
  // If this function fails it returns false.
  virtual bool Encrypt(const std::string& plaintext, std::string* ciphertext,
                       std::string* iv) const = 0;

  // See comments into openssl/aes.h
  virtual bool EncryptInit(std::string* iv) const = 0;

  virtual bool EncryptUpdate(const std::string& plaintext,
                             std::string* ciphertext) const = 0;

  virtual bool EncryptFinal(std::string* ciphertext) const = 0;

  // Decrypts |ciphertext| by using the required initialization vector |iv| and
  // put the result into |plaintext|. This function returns True on succcess.
  virtual bool Decrypt(const std::string& iv, const std::string& ciphertext,
                       std::string* plaintext) const = 0;

  // See comments into openssl/aes.h
  virtual bool DecryptInit(const std::string& iv) const = 0;

  virtual bool DecryptUpdate(const std::string& ciphertext,
                             std::string* plaintext) const = 0;

  virtual bool DecryptFinal(std::string* plaintext) const = 0;

  // Returns the secret key.
  virtual const std::string& GetKey() const = 0;

  // Returns the secret key's length. This value is expressed in bytes.
  virtual int GetKeySize() const = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(AESImpl);
};

}  // namespace keyczar

#endif  // KEYCZAR_AES_IMPL_H_
