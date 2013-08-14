// Copyright 2013 Google Inc.
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
#ifndef KEYCZAR_INTEROP_INTEROP_H_
#define KEYCZAR_INTEROP_INTEROP_H_

#include <string>

#include <keyczar/base/basictypes.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/values.h>

namespace keyczar {
namespace interop {

// Class used by interop for processing the command line and executing
// the appropriate commands.
class Interop {
 public:
  // |location_type| is used for instanciating the right reader and writer
  // when a key set is loaded or has to be written.
  Interop() {}

  // Processes command lines arguments |argv|
  static bool ProcessCommandLine(int argc, char** argv);

  bool DoProcessCommandLine(int argc, char** argv);

  // Creates the keys with the given parameters
  bool CmdCreate(const DictionaryValue* json) const;

  // Outputs the output of the generate operation for the given parameters.
  bool CmdGenerate(
      const DictionaryValue* json, std::string * json_output) const;

  // Tests the generate output provided
  bool CmdTest(const DictionaryValue* json) const;

 private:
  bool CallKeyczarTool(const ListValue * args) const;

  DISALLOW_COPY_AND_ASSIGN(Interop);
};

}  // namespace interop
}  // namespace keyczar

#endif  // KEYCZAR_INTEROP_INTEROP_H_
