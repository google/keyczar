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
#ifndef KEYCZAR_ECDSA_PUBLIC_KEY_H_
#define KEYCZAR_ECDSA_PUBLIC_KEY_H_

#include <string>

#include <keyczar/base/basictypes.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/values.h>
#include <keyczar/public_key.h>

namespace keyczar {

class ECDSAImpl;

class ECDSAPublicKey : public PublicKey {
 public:
  // Takes ownership of |ecdsa_impl|.
  ECDSAPublicKey(ECDSAImpl* ecdsa_impl, int size)
      : PublicKey(size), ecdsa_impl_(ecdsa_impl) {}

  // Creates a key from |root_key|. The caller takes ownership of the returned
  // Key.
  static ECDSAPublicKey* CreateFromValue(const Value& root_key);

  // The caller takes ownership of the returned Value.
  virtual Value* GetValue() const;

  virtual bool Hash(std::string* hash) const;

  virtual bool Verify(const std::string& data,
                      const std::string& signature) const;

 private:
  // The caller doesn't take ownership over the returned object.
  ECDSAImpl* ecdsa_impl() const { return ecdsa_impl_.get(); }

  scoped_ptr<ECDSAImpl> ecdsa_impl_;

  DISALLOW_COPY_AND_ASSIGN(ECDSAPublicKey);
};

}  // namespace keyczar

#endif  // KEYCZAR_ECDSA_PUBLIC_KEY_H_
