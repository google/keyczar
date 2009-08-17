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
#include <keyczar/key_util.h>

#include <keyczar/base/base64w.h>
#include <keyczar/base/stl_util-inl.h>

namespace keyczar {

namespace util {

bool DeserializeString(const DictionaryValue& node,
                       const std::string& key,
                       std::string* destination) {
  std::string temp;
  if (!node.GetString(key, &temp))
    return false;

  if (!base::Base64WDecode(temp, destination))
    return false;
  return true;
}

bool SafeDeserializeString(const DictionaryValue& node,
                           const std::string& key,
                           std::string* destination) {
  base::ScopedSafeString temp(new std::string());
  if (!node.GetString(key, temp.get()))
    return false;

  if (!base::Base64WDecode(*temp, destination))
    return false;
  return true;
}

bool SerializeString(const std::string& value,
                     const std::string& destination_key,
                     DictionaryValue* node) {
  if (node == NULL)
    return false;

  std::string temp;
  if (!base::Base64WEncode(value, &temp))
    return false;

  if (!node->SetString(destination_key, temp))
    return false;
  return true;
}

bool SafeSerializeString(const std::string& value,
                         const std::string& destination_key,
                         DictionaryValue* node) {
  if (node == NULL)
    return false;

  base::ScopedSafeString temp(new std::string());
  if (!base::Base64WEncode(value, temp.get()))
    return false;

  if (!node->SetString(destination_key, *temp))
    return false;
  return true;
}

}  // namespace util

}  // namespace keyczar
