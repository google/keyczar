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
#ifndef KEYCZAR_HMAC_KEY_H_
#define KEYCZAR_HMAC_KEY_H_

#include <string>

#include <keyczar/base/basictypes.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/values.h>
#include <keyczar/hmac_impl.h>
#include <keyczar/key.h>

namespace keyczar {

class HMACKey : public Key {
 public:
  // Takes ownership of |hmac_impl|.
  explicit HMACKey(HMACImpl* hmac_impl, int size)
      : Key(size), hmac_impl_(hmac_impl) {}

  // Creates a key from |root_key|. The caller takes ownership of the returned
  // Key.
  static HMACKey* CreateFromValue(const Value& root_key);

  // Generates a |size| bits key. The caller takes ownership of the returned
  // Key.
  static HMACKey* GenerateKey(int size);

  // The caller takes ownership of the returned Value.
  virtual Value* GetValue() const;

  virtual bool Hash(std::string* hash) const;

  virtual bool Sign(const std::string& data, std::string* signature) const;

  virtual bool Verify(const std::string& data,
                      const std::string& signature) const;

  // The caller doesn't take ownership over the returned HMACKey object.
  const HMACImpl* hmac_impl() const { return hmac_impl_.get(); }

 private:
  scoped_ptr<HMACImpl> hmac_impl_;

  DISALLOW_COPY_AND_ASSIGN(HMACKey);
};

}  // namespace keyczar

#endif  // KEYCZAR_HMAC_KEY_H_
