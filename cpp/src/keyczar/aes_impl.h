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

#include "base/basictypes.h"

namespace keyczar {

// Cryptographic AES interface.
class AESImpl {
 public:
  AESImpl() {}
  virtual ~AESImpl() {}

  // Encrypts |data| by using the optional initialization vector |iv| and
  // put the result into |encrypted|. If the initialization vector |iv| is
  // not required its value must be NULL. This function returns True on
  // succcess.
  virtual bool Encrypt(const std::string* iv, const std::string& data,
                       std::string* encrypted) const = 0;

  // Decrypts |encrypted| by using the optional initialization vector |iv| and
  // put the result into |data|. If the initialization vector |iv| is not
  // required its value must be NULL. This function returns True on succcess.
  virtual bool Decrypt(const std::string* iv, const std::string& encrypted,
                       std::string* data) const = 0;

  // Returns the secret key.
  virtual std::string GetKey() const = 0;

  // Returns the secret key's length. This value is expressed in bytes.
  virtual int GetKeySize() const = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(AESImpl);
};

}  // namespace keyczar

#endif  // KEYCZAR_AES_IMPL_H_
