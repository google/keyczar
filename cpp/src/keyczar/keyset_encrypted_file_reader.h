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
#ifndef KEYCZAR_KEYSET_ENCRYPTED_FILE_READER_H_
#define KEYCZAR_KEYSET_ENCRYPTED_FILE_READER_H_

#include <string>

#include "base/basictypes.h"
#include "base/file_path.h"
#include "base/scoped_ptr.h"
#include "base/values.h"

#include "keyczar/keyset_file_reader.h"

namespace keyczar {

class Crypter;

// An encrypted file reader is used for reading keys of encrypted keysets.
// In these keysets all the keys are encrypted and require an appropriate
// Crypter instance for decrypting them.
class KeysetEncryptedFileReader : public KeysetFileReader {
 public:
  // |dirname| is the path of the encrypted keyset and |crypter| is the Crypter
  // instance used for decrypting keys. This class takes ownership of |crypter|.
  KeysetEncryptedFileReader(const std::string& dirname, Crypter* crypter);

  KeysetEncryptedFileReader(const FilePath& dirname, Crypter* crypter);

  // This function transparently decrypts the key |version| and returns the
  // unencrypted value.
  virtual Value* ReadKey(int version) const;

 private:
  scoped_ptr<Crypter> crypter_;

  DISALLOW_COPY_AND_ASSIGN(KeysetEncryptedFileReader);
};

}  // namespace keyczar

#endif  // KEYCZAR_KEYSET_ENCRYPTED_FILE_READER_H_
