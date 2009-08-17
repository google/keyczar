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
#ifndef KEYCZAR_KEY_UTIL_H_
#define KEYCZAR_KEY_UTIL_H_

#include <string>

#include <keyczar/base/basictypes.h>
#include <keyczar/base/values.h>

namespace keyczar {

namespace util {

// Deserialize base64w encoded string associated to |key| in dictionary
// |node| and assign the result to |destination|. This function returns
// false if it fails.
bool DeserializeString(const DictionaryValue& node,
                       const std::string& key,
                       std::string* destination);

// Same than DeserializeString but the internal temp string is
// erased before delete.
bool SafeDeserializeString(const DictionaryValue& node,
                           const std::string& key,
                           std::string* destination);

// Seserialize |value| into a base64w encoded string and insert it into
// dictionary |node| at index |destination_key|. This function returns
// false if it fails.
bool SerializeString(const std::string& value,
                     const std::string& destination_key,
                     DictionaryValue* node);

// Same than SerializeString but the internal temp string is
// erased before delete.
bool SafeSerializeString(const std::string& value,
                         const std::string& destination_key,
                         DictionaryValue* node);

}  // namespace util

}  // namespace keyczar

#endif  // KEYCZAR_KEY_UTIL_H_
