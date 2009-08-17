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
#include <keyczar/ecdsa_impl.h>

#include <keyczar/base/logging.h>

namespace keyczar {

// static
std::string ECDSAImpl::GetCurveName(ECDSAImpl::Curve curve) {
  switch (curve) {
    case PRIME192V1:
      return std::string("prime192v1");
    case SECP224R1:
      return std::string("secp224r1");
    case PRIME256V1:
      return std::string("prime256v1");
    case SECP384R1:
      return std::string("secp384r1");
    default:
      NOTREACHED();
  }
  return std::string("");
}

// static
ECDSAImpl::Curve ECDSAImpl::GetCurve(const std::string& name) {
  if (name == "prime192v1")
    return PRIME192V1;
  if (name == "secp224r1")
    return SECP224R1;
  if (name == "prime256v1")
    return PRIME256V1;
  if (name == "secp384r1")
    return SECP384R1;

  NOTREACHED();
  return UNDEF;
}

// static
ECDSAImpl::Curve ECDSAImpl::GetCurveFromSize(int size) {
  switch (size) {
    case 192:
      return PRIME192V1;
    case 224:
      return SECP224R1;
    case 256:
      return PRIME256V1;
    case 384:
      return SECP384R1;
    default:
      NOTREACHED();
  }
  return UNDEF;
}

// static
int ECDSAImpl::GetSizeFromCurve(ECDSAImpl::Curve curve) {
  switch (curve) {
    case PRIME192V1:
      return 192;
    case SECP224R1:
      return 224;
    case PRIME256V1:
      return 256;
    case SECP384R1:
      return 384;
    default:
      NOTREACHED();
  }
  return 0;
}

}  // namespace keyczar
