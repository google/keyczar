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
#include <keyczar/cipher_mode.h>

#include <keyczar/base/logging.h>

namespace keyczar {

// static
CipherMode::Type CipherMode::GetTypeFromName(const std::string& name) {
  if (name == "CBC")
    return CBC;
  if (name == "CTR")
    return CTR;
  if (name == "ECB")
    return ECB;
  if (name == "DET_CBC")
    return DET_CBC;

  NOTREACHED();
  return UNDEF;
}

// static
std::string CipherMode::GetNameFromType(Type type) {
  switch (type) {
    case CBC:
      return "CBC";
    case CTR:
      return "CTR";
    case ECB:
      return "ECB";
    case DET_CBC:
      return "DET_CBC";
    default:
      NOTREACHED();
  }
  return "";
}

// static
bool CipherMode::HasIV(Type type) {
  switch (type) {
    case CBC:
    case CTR:
      return true;
    case ECB:
    case DET_CBC:
      return false;
    default:
      NOTREACHED();
  }
  return false;
}

// static
int CipherMode::GetOutputSize(Type type, int block_size, int input_length) {
  switch (type) {
    case CBC:
      return (input_length / block_size + 2) * block_size;
    case ECB:
      return block_size;
    case CTR:
      return input_length + block_size / 2;
    case DET_CBC:
      return (input_length / block_size + 1) * block_size;
    default:
      NOTREACHED();
  }
  return 0;
}

}  // namespace keyczar
