// Copyright 2012 Google Inc. All rights reserved.
//
// Author: Shawn Willden (swillden@google.com)
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

#ifndef KEYCZAR_RSA_PADDING_H_
#define KEYCZAR_RSA_PADDING_H_

namespace keyczar {

enum RsaPadding {
  UNDEFINED,
  OAEP,
  PKCS
};

}  // namespace keyczar

#endif  //  KEYCZAR_RSA_PADDING_H_
