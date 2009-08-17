// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This source code was copied from Chromium and was modified, any
// encountered errors are probably due to these modifications.

// This class works with command lines: building and parsing.
// Switches can optionally have a value attached using an equals sign,
// as in "-switch=value".  Arguments that aren't prefixed with a
// switch prefix are considered "loose parameters". Switch names are
// case-insensitive.  An argument of "--" will terminate switch
// parsing, causing everything after to be considered as loose
// parameters.

#ifndef KEYCZAR_BASE_COMMAND_LINE_H_
#define KEYCZAR_BASE_COMMAND_LINE_H_

#include <map>
#include <string>
#include <vector>

#include <keyczar/base/basictypes.h>
#include <keyczar/base/scoped_ptr.h>

namespace keyczar {
namespace base {

class CommandLine {
 public:
  // Initialize from an argv vector (or directly from main()'s argv).
  CommandLine(int argc, const char* const* argv);
  explicit CommandLine(const std::vector<std::string>& argv);

  // Construct a new, empty command line. |program| is the name of the
  // program to run (aka argv[0]).
  explicit CommandLine(const std::string& program);

  // Returns true if this command line contains the given switch.
  // (Switch names are case-insensitive.)
  bool HasSwitch(const std::string& switch_string) const;

  // Returns the value associated with the given switch.  If the
  // switch has no value or isn't present, this method returns
  // the empty string.
  std::string GetSwitchValue(const std::string& switch_string) const;

  // Get the remaining arguments to the command.
  std::vector<std::string> GetLooseValues() const;

  // Returns the original command line string as a vector of strings.
  const std::vector<std::string>& argv() const { return argv_; }

  // Returns the program part of the command line string (the first item).
  std::string program() const;

  // Appends the given switch string (preceded by a space and a switch
  // prefix) to the given string.
  void AppendSwitch(const std::string& switch_string);

  // Appends the given switch string (preceded by a space and a switch
  // prefix) to the given string, with the given value attached.
  void AppendSwitchWithValue(const std::string& switch_string,
                             const std::string& value_string);

  // Append a loose value to the command line.
  void AppendLooseValue(const std::string& value);

 private:
  // The argv array, with the program name in argv_[0].
  std::vector<std::string> argv_;

  // Parsed-out values.
  std::map<std::string, std::string> switches_;

  // Non-switch command-line arguments.
  std::vector<std::string> loose_values_;

  // Shared by the two POSIX constructor forms. Initalize from argv_.
  void InitFromArgv();

  // Returns true and fills in |switch_string| and |switch_value|
  // if |parameter_string| represents a switch.
  static bool IsSwitch(const std::string& parameter_string,
                       std::string* switch_string,
                       std::string* switch_value);

  DISALLOW_COPY_AND_ASSIGN(CommandLine);
};

}  // namespace base
}  // namespace keyczar

#endif  // KEYCZAR_BASE_COMMAND_LINE_H_
