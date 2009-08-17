// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <vector>

#include <keyczar/base/basictypes.h>
#include <keyczar/base/command_line.h>
#include <keyczar/base/logging.h>
#include <keyczar/base/string_util.h>

#include <testing/gtest/include/gtest/gtest.h>

namespace keyczar {
namespace base {

TEST(CommandLineTest, CommandLineConstructor) {
  const char* argv[] = {"program", "--foo=", "-bar",
                        "-spaetzel=pierogi", "-baz", "flim",
                        "--other-switches=--dog=canine --cat=feline",
                        "-spaetzle=Crepe", "-=loosevalue", "flan",
                        "--input-translation=45--output-rotation",
                        "--", "--", "--not-a-switch",
                        "in the time of submarines..."};
  CommandLine cl(arraysize(argv), argv);

  EXPECT_FALSE(cl.HasSwitch("cruller"));
  EXPECT_FALSE(cl.HasSwitch("flim"));
  EXPECT_FALSE(cl.HasSwitch("program"));
  EXPECT_FALSE(cl.HasSwitch("dog"));
  EXPECT_FALSE(cl.HasSwitch("cat"));
  EXPECT_FALSE(cl.HasSwitch("output-rotation"));
  EXPECT_FALSE(cl.HasSwitch("not-a-switch"));
  EXPECT_FALSE(cl.HasSwitch("--"));

  EXPECT_EQ("program", cl.program());

  EXPECT_TRUE(cl.HasSwitch("foo"));
  EXPECT_TRUE(cl.HasSwitch("bar"));
  EXPECT_TRUE(cl.HasSwitch("baz"));
  EXPECT_TRUE(cl.HasSwitch("spaetzle"));

  EXPECT_TRUE(cl.HasSwitch("other-switches"));
  EXPECT_TRUE(cl.HasSwitch("input-translation"));

  EXPECT_EQ("Crepe", cl.GetSwitchValue("spaetzle"));
  EXPECT_EQ("", cl.GetSwitchValue("Foo"));
  EXPECT_EQ("", cl.GetSwitchValue("bar"));
  EXPECT_EQ("", cl.GetSwitchValue("cruller"));
  EXPECT_EQ("--dog=canine --cat=feline", cl.GetSwitchValue("other-switches"));
  EXPECT_EQ("45--output-rotation", cl.GetSwitchValue("input-translation"));

  std::vector<std::string> loose_values = cl.GetLooseValues();
  ASSERT_EQ(5U, loose_values.size());

  std::vector<std::string>::const_iterator iter = loose_values.begin();
  EXPECT_EQ("flim", *iter);
  ++iter;
  EXPECT_EQ("flan", *iter);
  ++iter;
  EXPECT_EQ("--", *iter);
  ++iter;
  EXPECT_EQ("--not-a-switch", *iter);
  ++iter;
  EXPECT_EQ("in the time of submarines...", *iter);
  ++iter;
  EXPECT_TRUE(iter == loose_values.end());

  const std::vector<std::string>& argvec = cl.argv();

  for (size_t i = 0; i < argvec.size(); i++) {
    EXPECT_EQ(0, argvec[i].compare(argv[i]));
  }
}

// Tests behavior with an empty input string.
TEST(CommandLineTest, EmptyString) {
  CommandLine cl(0, NULL);
  EXPECT_EQ(cl.argv().size(), 0);
  EXPECT_EQ(0U, cl.GetLooseValues().size());
}

// Test methods for appending switches to a command line.
TEST(CommandLineTest, AppendSwitches) {
  std::string switch1 = "switch1";
  std::string switch2 = "switch2";
  std::string value = "value";
  std::string switch3 = "switch3";
  std::string value3 = "a value with spaces";
  std::string switch4 = "switch4";
  std::string value4 = "\"a value with quotes\"";

  std::vector<std::string> argv;
  argv.push_back(std::string("Program"));
  CommandLine cl(argv);

  cl.AppendSwitch(switch1);
  cl.AppendSwitchWithValue(switch2, value);
  cl.AppendSwitchWithValue(switch3, value3);
  cl.AppendSwitchWithValue(switch4, value4);

  EXPECT_TRUE(cl.HasSwitch(switch1));
  EXPECT_TRUE(cl.HasSwitch(switch2));
  EXPECT_EQ(value, cl.GetSwitchValue(switch2));
  EXPECT_TRUE(cl.HasSwitch(switch3));
  EXPECT_EQ(value3, cl.GetSwitchValue(switch3));
  EXPECT_TRUE(cl.HasSwitch(switch4));
  EXPECT_EQ(value4, cl.GetSwitchValue(switch4));
}

}  // namespace base
}  // namespace keyczar
