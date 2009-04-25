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
#ifndef KEYCZAR_KEYSET_ENCRYPTED_FILE_WRITER_H_
#define KEYCZAR_KEYSET_ENCRYPTED_FILE_WRITER_H_

#include <string>

#include "base/basictypes.h"
#include "base/file_path.h"
#include "base/scoped_ptr.h"
#include "base/values.h"

#include "keyczar/keyset_file_writer.h"

namespace keyczar {

class Encrypter;

// An encrypted file writer is used for writing encrypted keys. A encrypter
// is used for encrypting the keys before writing them to destination files.
class KeysetEncryptedFileWriter : public KeysetFileWriter {
 public:
  // |dirname| is the path of the encrypted keyset and |encrypter| is the
  // Encrypter instance used for encrypting keys. This class takes ownership
  // of |encrypter|.
  KeysetEncryptedFileWriter(const std::string& dirname, Encrypter* encrypter);

  KeysetEncryptedFileWriter(const FilePath& dirname, Encrypter* encrypter);

  // Transparently encrypts |key| and writes it to |version| inside the keyset
  // path. Returns true on success.
  virtual bool WriteKey(const Value* key, int version) const;

 private:
  scoped_ptr<Encrypter> encrypter_;

  DISALLOW_COPY_AND_ASSIGN(KeysetEncryptedFileWriter);
};

}  // namespace keyczar

#endif  // KEYCZAR_KEYSET_ENCRYPTED_FILE_WRITER_H_
