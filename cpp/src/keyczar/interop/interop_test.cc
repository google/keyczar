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
#include <keyczar/interop/interop_test.h>

#include <keyczar/base/base64w.h>
#include <keyczar/base/json_reader.h>
#include <keyczar/base/json_writer.h>
#include <keyczar/base/logging.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/keyczar_tool/keyczar_tool.h>
#include <keyczar/interop/operation.h>

#include <iostream>

int main(int argc, char** argv) {
  // Before any cryptographic operation initialize the random engine
  // (seeding...). However this step is useless under Linux with OpenSSL.
  keyczar::CryptoFactory::Rand();

  // Turn off all logging, perhaps there is a better way to do this.
  SetLogHandler(NULL);

  if (!keyczar::interop::Interop::ProcessCommandLine(argc, argv))
    return 1;
  return 0;
}

namespace keyczar {
namespace interop {


// static
bool Interop::ProcessCommandLine(int argc, char** argv) {
  Interop interop_tester;
  return interop_tester.DoProcessCommandLine(argc, argv);
}

bool Interop::DoProcessCommandLine(int argc, char** argv) {
  if (argc != 2) {
    std::cout << "Incorrect Number of Arguments" << std::endl;
    return false;
  }
  scoped_ptr<const Value> command_json(
      base::JSONReader::Read(argv[1], false /* allow_trailing_comma */));
  if (command_json.get() == NULL
      || !command_json->IsType(Value::TYPE_DICTIONARY))
    return false;

  const DictionaryValue* command_dict
      = static_cast<const DictionaryValue*>(command_json.get());
  std::string command;

  if (!command_dict->GetString("command", &command)) {
    std::cout << "Command argument not present" << std::endl;
    return false;
  }
  if (command == "create") {
    return CmdCreate(command_dict);
  } else if (command == "generate") {
    std::string output;
    if (!CmdGenerate(command_dict, &output)) {
      return false;
    }
    std::cout << output << std::endl;
    return true;
  } else if (command == "test") {
    return CmdTest(command_dict);
  } else {
    std::cout << "Command " << command << " does not exist" << std::endl;
    return false;
  }
}

bool Interop::CallKeyczarTool(const ListValue * args) const {
  std::string cpp_string;
  int argc = args->GetSize() + 1;
  const char* argv[argc];
  argv[0] = "keyczart";
  for (int i = 0; i < args->GetSize(); i++) {
    if (!args->GetString(i, &cpp_string))
      return false;
    argv[i + 1] = cpp_string.c_str();
  }
  return keyczar::keyczar_tool::KeyczarTool::ProcessCommandLine(
          keyczar::keyczar_tool::KeyczarTool::JSON_FILE, argc, argv);
}

bool Interop::CmdCreate(const DictionaryValue* json) const {
  ListValue* commands;
  ListValue* args;

  if (!json->GetList("keyczartCommands", &commands)) {
    std::cout << "keyczartCommands not found in json" << std::endl;
    return false;
  }
  
  for (int i = 0; i < commands->GetSize(); i++) {
    if (!commands->GetList(i, &args) || !CallKeyczarTool(args))
      return false;
  }
  return true;
}

bool Interop::CmdGenerate(
    const DictionaryValue* json, std::string * json_output) const {
  std::string output, operation, key_path, algorithm, test_data;
  DictionaryValue * generate_options;

  if (!json->GetString("operation", &operation) ||
      !json->GetString("keyPath", &key_path) ||
      !json->GetString("algorithm", &algorithm) ||
      !json->GetString("testData", &test_data) ||
      !json->GetDictionary("generateOptions", &generate_options)) {
    std::cout << "Incorrect parameters in generate json" << std::endl;
    return false;
  }

  Operation* op = Operation::GetOperationByName(operation, key_path, test_data);
  if (!op->Generate(algorithm, generate_options, &output) ||
      !op->OutputToJson(output, json_output)) {
    return false;
  }
  return true;
}

bool Interop::CmdTest(const DictionaryValue* json) const {
  std::string output, operation, key_path, algorithm, test_data;
  DictionaryValue* generate_options;
  DictionaryValue* test_options;
  DictionaryValue* json_output;

  if (!json->GetString("operation", &operation) ||
      !json->GetString("keyPath", &key_path) ||
      !json->GetString("algorithm", &algorithm) ||
      !json->GetString("testData", &test_data) ||
      !json->GetDictionary("output", &json_output) ||
      !json->GetDictionary("generateOptions", &generate_options) ||
      !json->GetDictionary("testOptions", &test_options)) {
    std::cout << "Incorrect parameters in test json" << std::endl;
    return false;
  }

  Operation* op = Operation::GetOperationByName(operation, key_path, test_data);
  if (!op->Test(json_output, algorithm, generate_options, test_options)) {
    std::cout << "Test failed" << std::endl;
    return false;
  }
  return true;
}

}  // namespace interop
}  // namespace keyczar
