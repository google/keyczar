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
#ifndef KEYCZAR_OPENSSL_RAND_H_
#define KEYCZAR_OPENSSL_RAND_H_

#include <openssl/rand.h>

#include <string>

#include <keyczar/base/basictypes.h>
#include <keyczar/openssl/util.h>
#include <keyczar/rand_impl.h>

namespace keyczar {

namespace openssl {

// OpenSSL concrete implementation.
class RandOpenSSL : public RandImpl {
 public:
  RandOpenSSL() : is_initialized_(false) {}
  ~RandOpenSSL() {}

  virtual bool Init();

  virtual bool is_initialized() const { return is_initialized_; }

  // Returns |num| cryptographically strong pseudo-random bytes in |bytes|.
  // This function returns false if it fails.
  virtual bool RandBytes(int num, std::string* bytes) const;

 private:
  bool is_initialized_;

  DISALLOW_COPY_AND_ASSIGN(RandOpenSSL);
};

}  // namespace openssl

}  // namespace keyczar

#endif  // KEYCZAR_OPENSSL_RAND_H_
