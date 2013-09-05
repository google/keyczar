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
#ifndef KEYCZAR_INTEROP_OPERATION_H_
#define KEYCZAR_INTEROP_OPERATION_H_

#include <string>

#include <keyczar/base/basictypes.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/values.h>
#include <keyczar/rw/keyset_reader.h>

namespace keyczar {
namespace interop {

class Operation {
 public:
  Operation(const std::string& key_path, const std::string& test_data) :
  key_path_(key_path), test_data_(test_data) {}

  static Operation * GetOperationByName(
      const std::string& name, const std::string& key_path,
      const std::string& test_data);

  virtual bool Generate(
      const std::string& algorithm, const DictionaryValue * generate_params,
      std::string * output) = 0;

  virtual bool Test(
      const DictionaryValue * output, const std::string& algorithm,
      const DictionaryValue * generate_params,
      const DictionaryValue * test_params) = 0;

  virtual bool OutputToJson(
      const std::string& output, std::string * json_string);

  virtual bool InputFromJson(
      const DictionaryValue * json, std::string * output);

 protected:
  const std::string GetKeyPath(const std::string& algorithm);

  rw::KeysetReader* GetReader(
      const std::string& algorithm, const std::string& crypter,
      const std::string& publicKey);

  const std::string key_path_;
  const std::string test_data_;

 private:
  DISALLOW_COPY_AND_ASSIGN(Operation);
};

class UnversionedSignOperation : public Operation {
 public:
  UnversionedSignOperation(
      const std::string& key_path, const std::string& test_data) :
  Operation(key_path, test_data) {}

  virtual bool Generate(
      const std::string& algorithm, const DictionaryValue * generate_params,
      std::string * output);

  virtual bool Test(
      const DictionaryValue * output, const std::string& algorithm,
      const DictionaryValue * generate_params,
      const DictionaryValue * test_params);

 private:
  DISALLOW_COPY_AND_ASSIGN(UnversionedSignOperation);
};

class SignedSessionOperation : public Operation {
 public:
  SignedSessionOperation(
      const std::string& key_path, const std::string& test_data) :
  Operation(key_path, test_data) {}

  virtual bool Generate(
      const std::string& algorithm, const DictionaryValue * generate_params,
      std::string * output);

  virtual bool Test(
      const DictionaryValue * output, const std::string& algorithm,
      const DictionaryValue * generate_params,
      const DictionaryValue * test_params);

  virtual bool OutputToJson(
      const std::string& output, std::string * json_string);

 private:
  DISALLOW_COPY_AND_ASSIGN(SignedSessionOperation);
};

class SignOperation : public Operation {
 public:
  SignOperation(const std::string& key_path, const std::string& test_data) :
  Operation(key_path, test_data) {}

  virtual bool Generate(
      const std::string& algorithm, const DictionaryValue * generate_params,
      std::string * output);

  virtual bool Test(
      const DictionaryValue * output, const std::string& algorithm,
      const DictionaryValue * generate_params,
      const DictionaryValue * test_params);

 private:
  DISALLOW_COPY_AND_ASSIGN(SignOperation);
};

class AttachedSignOperation : public Operation {
 public:
  AttachedSignOperation(
      const std::string& key_path, const std::string& test_data) :
  Operation(key_path, test_data) {}

  virtual bool Generate(
      const std::string& algorithm, const DictionaryValue * generate_params,
      std::string * output);

  virtual bool Test(
      const DictionaryValue * output, const std::string& algorithm,
      const DictionaryValue * generate_params,
      const DictionaryValue * test_params);

 private:
  DISALLOW_COPY_AND_ASSIGN(AttachedSignOperation);
};

class EncryptOperation : public Operation {
 public:
  EncryptOperation(const std::string& key_path, const std::string& test_data) :
  Operation(key_path, test_data) {}

  virtual bool Generate(
      const std::string& algorithm, const DictionaryValue * generate_params,
      std::string * output);

  virtual bool Test(
      const DictionaryValue * output, const std::string& algorithm,
      const DictionaryValue * generate_params,
      const DictionaryValue * test_params);

 private:
  DISALLOW_COPY_AND_ASSIGN(EncryptOperation);
};

}  // namespace interop
}  // namespace keyczar

#endif  // KEYCZAR_INTEROP_OPERATION_H_
