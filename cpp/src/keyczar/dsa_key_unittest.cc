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
#include <string>

#include <testing/gtest/include/gtest/gtest.h>

#include <keyczar/base/base64w.h>
#include <keyczar/base/logging.h>
#include <keyczar/base/ref_counted.h>
#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/values.h>
#include <keyczar/dsa_private_key.h>
#include <keyczar/dsa_public_key.h>
#include <keyczar/key_type.h>
#include <keyczar/keyczar_test.h>
#include <keyczar/keyset_file_reader.h>

namespace keyczar {

class DSATest : public KeyczarTest {
 protected:
  // Loads public key from JSON file.
  scoped_refptr<DSAPublicKey> LoadDSAPublicKey(const FilePath& path,
                                               int key_version) {
    KeysetFileReader reader(path);
    scoped_ptr<Value> value(reader.ReadKey(key_version));
    EXPECT_NE(static_cast<Value*>(NULL), value.get());
    scoped_refptr<DSAPublicKey> public_key(DSAPublicKey::CreateFromValue(
                                               *value));
    CHECK(public_key);
    return public_key;
  }
};

TEST_F(DSATest, GenerateSignAndVerify) {
  scoped_ptr<KeyType> dsa_type(KeyType::Create("DSA_PRIV"));
  ASSERT_TRUE(dsa_type.get());
  const std::vector<int> sizes = dsa_type->sizes();

  scoped_refptr<DSAPrivateKey> private_key;
  for (std::vector<int>::const_iterator iter = sizes.begin();
       iter != sizes.end(); ++iter) {
    // Generates a new private key.
    private_key = DSAPrivateKey::GenerateKey(*iter);
    ASSERT_TRUE(private_key.get());

    // Attempts to sign and verify input data.
    std::string signature;
    EXPECT_TRUE(private_key->Sign(input_data_, &signature));
    EXPECT_TRUE(private_key->Verify(input_data_, signature));
  }
}

TEST_F(DSATest, VerifyDumpedSignature) {
  FilePath pub_path = data_path_.Append("dsa.public");
  scoped_refptr<DSAPublicKey> public_key = LoadDSAPublicKey(pub_path, 2);

  // Try to verify the signature file
  std::string b64w_signature;
  FilePath signature_file = data_path_.Append("dsa");
  signature_file = signature_file.AppendASCII("2.out");
  EXPECT_TRUE(file_util::ReadFileToString(signature_file,
                                          &b64w_signature));
  std::string signature;
  EXPECT_TRUE(Base64WDecode(b64w_signature, &signature));

  // Checks signature
  input_data_.push_back(Key::GetVersionByte());
  EXPECT_TRUE(public_key->Verify(input_data_,
                                 signature.substr(
                                     Key::GetHeaderSize())));
}

TEST_F(DSATest, LoadPEMKey) {
  const FilePath dsa_pem_path = data_path_.AppendASCII("dsa_pem");
  scoped_refptr<DSAPrivateKey> private_key;

  const FilePath simple_key = dsa_pem_path.AppendASCII("dsa_priv.pem");
  private_key = DSAPrivateKey::CreateFromPEMKey(simple_key.value(), NULL);
  EXPECT_TRUE(private_key);

  const std::string passphrase("cartman");
  const FilePath protected_key = dsa_pem_path.AppendASCII(
      "dsa_priv_encrypted.pem");
  private_key = DSAPrivateKey::CreateFromPEMKey(protected_key.value(),
                                                &passphrase);
  EXPECT_TRUE(private_key);

  // Attempts to sign and verify input data.
  std::string signature;
  EXPECT_TRUE(private_key->Sign(input_data_, &signature));
  EXPECT_TRUE(private_key->Verify(input_data_, signature));
}

}  // namespace keyczar
