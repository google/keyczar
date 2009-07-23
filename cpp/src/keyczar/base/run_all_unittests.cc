// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This source code was copied from Chromium and has been modified to fit
// with Keyczar, any encountered errors are probably due to these
// modifications.

#include <testing/gtest/include/gtest/gtest.h>

#include <keyczar/base/command_line.h>

int main(int argc, char** argv) {
  CommandLine::Init(argc, argv);
  testing::InitGoogleTest(&argc, argv);

  int result = RUN_ALL_TESTS();
  return result;
}
