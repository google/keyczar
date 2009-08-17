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
#ifndef KEYCZAR_ECDSA_IMPL_H_
#define KEYCZAR_ECDSA_IMPL_H_

#include <string>

#include <keyczar/base/basictypes.h>
#include <keyczar/base/stl_util-inl.h>

namespace keyczar {

// Cryptographic ECDSA interface.
class ECDSAImpl {
 public:
  // List of supported curves.
  enum Curve {
    UNDEF,
    PRIME192V1,
    SECP224R1,
    PRIME256V1,
    SECP384R1
  };

  // This structure will be used for retrieving in a generic way the values
  // of these fields from the concrete implementations.
  struct ECDSAIntermediateKey {
    Curve curve;              // Normalized curve type
    std::string public_key;   // Public key bytes
    std::string private_key;  // Private key bytes

    ~ECDSAIntermediateKey() {
      base::STLStringMemErase(&private_key);
    }
  };

  ECDSAImpl() {}
  virtual ~ECDSAImpl() {}

  virtual bool ExportPrivateKey(const std::string& filename,
                                const std::string* passphrase) const = 0;

  // Through this method the concrete implementation copies all its internal
  // private and public fields into |key|. This function returns true on
  // success.
  virtual bool GetAttributes(ECDSAIntermediateKey* key) = 0;

  // In this case only public attributes are copied into |key|.
  virtual bool GetPublicAttributes(ECDSAIntermediateKey* key) = 0;

  virtual bool Sign(const std::string& message,
                    std::string* signature) const = 0;

  virtual bool Verify(const std::string& message,
                      const std::string& signature) const = 0;

  // Returns the exact key size in bits NOT the size rounded up to next byte.
  virtual int Size() const = 0;

  static std::string GetCurveName(Curve curve);

  static Curve GetCurve(const std::string& name);

  static Curve GetCurveFromSize(int size);

  // Returns 0 if it fails.
  static int GetSizeFromCurve(Curve curve);

 private:
  DISALLOW_COPY_AND_ASSIGN(ECDSAImpl);
};

}  // namespace keyczar

#endif  // KEYCZAR_ECDSA_IMPL_H_
