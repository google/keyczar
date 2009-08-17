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
#ifndef KEYCZAR_HMAC_IMPL_H_
#define KEYCZAR_HMAC_IMPL_H_

#include <string>

#include <keyczar/base/basictypes.h>

namespace keyczar {

// Cryptographic HMAC interface.
class HMACImpl {
 public:
  // List of supported digest algorithms. This type is used for
  // communicating the algorithm to be used by the concrete
  // implementations.
  enum DigestAlgorithm {
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512
  };

  HMACImpl() {}
  virtual ~HMACImpl() {}

  // This function initializes the concrete hmac accumulator. This
  // function returns true on success.
  virtual bool Init() = 0;

  // Adds |data| to hmac. This function returns true on success.
  virtual bool Update(const std::string& data) = 0;

  // Finalizes the hmac value and copy the result into |digest|. This function
  // returns true on success.
  virtual bool Final(std::string* digest) = 0;

  // This function spare the calls to the three previous methods: Init(),
  // Update() and Final(). |digest| will hold the final message digest
  // computed from |data|. It returns true on success.
  bool Digest(const std::string& data, std::string* digest);

  virtual const std::string& GetKey() const = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(HMACImpl);
};

}  // namespace keyczar

#endif  // KEYCZAR_HMAC_IMPL_H_
