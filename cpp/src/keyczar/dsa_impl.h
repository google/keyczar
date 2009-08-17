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
#ifndef KEYCZAR_DSA_IMPL_H_
#define KEYCZAR_DSA_IMPL_H_

#include <string>

#include <keyczar/base/basictypes.h>
#include <keyczar/base/stl_util-inl.h>

namespace keyczar {

// Cryptographic DSA interface.
class DSAImpl {
 public:
  // This structure will be used for retrieving in a generic way the values
  // of these fields from the concrete implementations.
  struct DSAIntermediateKey {
    std::string p;     // prime number (public)
    std::string q;     // 160-bit subprime, q | p-1 (public)
    std::string g;     // generator of subgroup (public)
    std::string y;     // public key exponent
    std::string x;     // private key

    ~DSAIntermediateKey() {
      base::STLStringMemErase(&x);
    }
  };

  DSAImpl() {}
  virtual ~DSAImpl() {}

  virtual bool ExportPrivateKey(const std::string& filename,
                                const std::string* passphrase) const = 0;

  // Through this method the concrete implementation copies all its internal
  // private and public fields into |key|. This function returns true on
  // success.
  virtual bool GetAttributes(DSAIntermediateKey* key) = 0;

  // In this case only public attributes are copied into |key|.
  virtual bool GetPublicAttributes(DSAIntermediateKey* key) = 0;

  virtual bool Sign(const std::string& message,
                    std::string* signature) const = 0;

  virtual bool Verify(const std::string& message,
                      const std::string& signature) const = 0;

  // Returns the key size in bits.
  virtual int Size() const = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(DSAImpl);
};

}  // namespace keyczar

#endif  // KEYCZAR_DSA_IMPL_H_
