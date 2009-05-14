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
#ifndef KEYCZAR_KEYCZAR_TOOL_H_
#define KEYCZAR_KEYCZAR_TOOL_H_

#include <string>

#include "base/basictypes.h"
#include "base/command_line.h"

#include "keyczar/key_purpose.h"
#include "keyczar/key_status.h"
#include "keyczar/keyset_file_reader.h"
#include "keyczar/keyset_file_writer.h"
#include "keyczar/keyset_reader.h"
#include "keyczar/keyset_writer.h"

namespace keyczar {

namespace keyczar_tool {

// Class used by keyczart for processing the command line and executing
// the appropriate commands.
class KeyczarTool {
 public:
  enum LocationType {
    // Locations represent directories containing metadata and
    // keys files.
    DISK
  };

  explicit KeyczarTool(LocationType location_type)
      : location_type_(location_type), command_line_(NULL) {}

  // This function must be called before ProcessCommandLine().
  bool Init(int argc, char** argv);

  // This method processes the command line and calls the corresponding
  // command Cmd<command> with the required arguments.
  bool ProcessCommandLine();

  bool CmdCreate(const std::string& location, const KeyPurpose& key_purpose,
                 const std::string& name, const std::string& asymmetric) const;

  bool CmdAddKey(const std::string& location, const KeyStatus& key_status,
                 int size, const std::string& crypter_location) const;

  bool CmdImportKey(const std::string& location, const KeyStatus& key_status,
                    const std::string& filename, const std::string* passphrase,
                    const std::string& crypter_location) const;

  bool CmdPubKey(const std::string& location, const std::string& destination,
                 const std::string& crypter_location) const;

  bool CmdPromote(const std::string& location, int version) const;

  bool CmdDemote(const std::string& location, int version) const;

  bool CmdRevoke(const std::string& location, int version) const;

 private:
  // Factory method returns a reader object. The Reader's class is determined
  // by the value of |location_type_|.
  KeysetReader* GetReader(const std::string& location,
                          const std::string& crypter_location) const;

  // Factory method returns a writer object. The Writer's class is determined
  // by the value of |location_type_|.
  KeysetWriter* GetWriter(const std::string& location,
                          const std::string& crypter_location) const;

  KeysetFileReader* GetFileReader(const std::string& location,
                                  const std::string& crypter_location) const;

  KeysetFileWriter* GetFileWriter(const std::string& location,
                                  const std::string& crypter_location) const;

  // Will be used to decide which reader and writer to instanciate.
  LocationType location_type_;

  CommandLine* command_line_;

  DISALLOW_COPY_AND_ASSIGN(KeyczarTool);
};

}  // namespace keyczar_tool

}  // namespace keyczar

#endif  // KEYCZAR_KEYCZAR_TOOL_H_
