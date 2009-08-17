// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <keyczar/base/command_line.h>

#include <algorithm>

#include <keyczar/base/logging.h>
#include <keyczar/base/string_util.h>

namespace {

static const char* const kSwitchPrefixes[] = {"--", "-"};
static const char kSwitchTerminator[] = "--";
static const char kSwitchValueSeparator[] = "=";

}  // namespace

namespace keyczar {
namespace base {

CommandLine::CommandLine(int argc, const char* const* argv) {
  for (int i = 0; i < argc; ++i) {
    argv_.push_back(argv[i]);
  }
  InitFromArgv();
}

CommandLine::CommandLine(const std::vector<std::string>& argv) {
  argv_ = argv;
  InitFromArgv();
}

void CommandLine::InitFromArgv() {
  bool parse_switches = true;
  for (size_t i = 1; i < argv_.size(); ++i) {
    const std::string& arg = argv_[i];
    CHECK(IsStringUTF8(arg));

    if (!parse_switches) {
      loose_values_.push_back(arg);
      continue;
    }

    if (arg == kSwitchTerminator) {
      parse_switches = false;
      continue;
    }

    std::string switch_string;
    std::string switch_value;
    if (IsSwitch(arg, &switch_string, &switch_value)) {
      switches_[switch_string] = switch_value;
    } else {
      loose_values_.push_back(arg);
    }
  }
}

CommandLine::CommandLine(const std::string& program) {
  argv_.push_back(program);
}

// static
bool CommandLine::IsSwitch(const std::string& parameter_string,
                           std::string* switch_string,
                           std::string* switch_value) {
  switch_string->clear();
  switch_value->clear();

  for (size_t i = 0; i < arraysize(kSwitchPrefixes); ++i) {
    std::string prefix(kSwitchPrefixes[i]);
    if (parameter_string.find(prefix) != 0)
      continue;

    const size_t switch_start = prefix.length();
    const size_t equals_position = parameter_string.find(
        kSwitchValueSeparator, switch_start);
    std::string switch_native;
    if (equals_position == std::string::npos) {
      switch_native = parameter_string.substr(switch_start);
    } else {
      switch_native = parameter_string.substr(
          switch_start, equals_position - switch_start);
      *switch_value = parameter_string.substr(equals_position + 1);
    }
    *switch_string = switch_native;

    return true;
  }

  return false;
}

bool CommandLine::HasSwitch(const std::string& switch_string) const {
  return switches_.find(switch_string) != switches_.end();
}

std::string CommandLine::GetSwitchValue(
    const std::string& switch_string) const {
  std::map<std::string, std::string>::const_iterator result =
      switches_.find(switch_string);

  if (result == switches_.end())
    return "";
  return result->second;
}

std::vector<std::string> CommandLine::GetLooseValues() const {
  std::vector<std::string> values;
  for (size_t i = 0; i < loose_values_.size(); ++i)
    values.push_back(loose_values_[i]);
  return values;
}

std::string CommandLine::program() const {
  DCHECK(argv_.size() > 0);
  return argv_[0];
}

void CommandLine::AppendSwitch(const std::string& switch_string) {
  argv_.push_back(kSwitchPrefixes[0] + switch_string);
  switches_[switch_string] = "";
}

void CommandLine::AppendSwitchWithValue(const std::string& switch_string,
                                        const std::string& value_string) {
  argv_.push_back(kSwitchPrefixes[0] + switch_string +
                  kSwitchValueSeparator + value_string);
  switches_[switch_string] = value_string;
}

void CommandLine::AppendLooseValue(const std::string& value) {
  argv_.push_back(value);
}

}  // namespace base
}  // namespace keyczar
