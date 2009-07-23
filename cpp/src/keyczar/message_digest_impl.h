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
#ifndef KEYCZAR_MESSAGE_DIGEST_IMPL_H_
#define KEYCZAR_MESSAGE_DIGEST_IMPL_H_

#include <string>

#include <keyczar/base/basictypes.h>

namespace keyczar {

// Cryptographic Message Digest interface.
class MessageDigestImpl {
 public:
  // List of supported digest algorithms. This type is used for
  // communicating the algorithm to use to the concrete implementations.
  enum DigestAlgorithm {
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
  };

  explicit MessageDigestImpl(const DigestAlgorithm digest_algorithm)
      : digest_algorithm_(digest_algorithm) {}

  virtual ~MessageDigestImpl() {}

  // This function initializes the concrete message digest accumulator. This
  // function returns true on success.
  virtual bool Init() = 0;

  // Adds |data| to hash. This function returns true on success.
  virtual bool Update(const std::string& data) = 0;

  // Finalizes the hash value and copy the result into |digest|. This function
  // returns true on success.
  virtual bool Final(std::string* digest) = 0;

  // This function spare the calls to the three previous methods: Init(),
  // Update() and Final(). |digest| will hold the final message digest
  // computed from |data|. It returns true on success.
  bool Digest(const std::string& data, std::string* digest);

  // Returns the size of the message digest i.e. the hash.
  virtual int Size() const = 0;

  DigestAlgorithm digest_algorithm() const { return digest_algorithm_; }

 private:
  const DigestAlgorithm digest_algorithm_;

  DISALLOW_COPY_AND_ASSIGN(MessageDigestImpl);
};

}  // namespace keyczar

#endif  // KEYCZAR_MESSAGE_DIGEST_IMPL_H_
