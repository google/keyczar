// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "base/base64.h"
#include "base/modp/modp_b64.h"

bool Base64Encode(const std::string& input, std::string* output) {
  output->assign(modp::b64_encode(input));
  if (output->empty())
    return false;
  return true;
}

bool Base64Decode(const std::string& input, std::string* output) {
  output->assign(modp::b64_decode(input));
  if (output->empty())
    return false;
  return true;
}
