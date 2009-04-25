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
#ifndef KEYCZAR_KEYSET_FILE_WRITER_H_
#define KEYCZAR_KEYSET_FILE_WRITER_H_

#include <string>

#include "base/basictypes.h"
#include "base/file_path.h"
#include "base/values.h"

#include "keyczar/key.h"
#include "keyczar/keyset.h"
#include "keyczar/keyset_metadata.h"
#include "keyczar/keyset_writer.h"

namespace keyczar {

// Concrete class for writing metadata and keys to disk files. This class also
// implements an Observer class which will provide notifications when data
// has to be written.
class KeysetFileWriter : public KeysetWriter, public Keyset::Observer {
 public:
  // |dirname| is the string path of the keyset to read.
  explicit KeysetFileWriter(const std::string& dirname);

  // |dirname| is the FilePath of the keyset to read.
  explicit KeysetFileWriter(const FilePath& dirname);

  // Writes |metadata| to file 'meta' inside the keyset directory.
  virtual bool WriteMetadata(const Value* metadata) const;

  // Writes |key| to file |version| inside the keyset directory.
  virtual bool WriteKey(const Value* key, int version) const;

  // Function automatically called when the metadata has changed and must be
  // written on disk.
  virtual void OnUpdatedKeysetMetadata(const KeysetMetadata& key_metadata);

  // Function automatically called when a new key is added to a keyset.
  // Therefore this key must also be written on disk.
  virtual void OnNewKey(const Key& key, int version_number);

  // Function automatically called when a key was revoked. Currently this
  // function does nothing but the key |version_number| could be deleted
  // from disk as well.
  virtual void OnRevokedKey(int version_number);

  FilePath dirname() const { return dirname_; }

 private:
  const FilePath dirname_;
  const FilePath metadata_basename_;

  DISALLOW_COPY_AND_ASSIGN(KeysetFileWriter);
};

}  // namespace keyczar

#endif  // KEYCZAR_KEYSET_FILE_WRITER_H_
