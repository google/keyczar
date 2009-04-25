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

#include "base/base64w.h"
#include "base/logging.h"
#include "base/ref_counted.h"
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/path_service.h"
#include "base/scoped_ptr.h"
#include "base/values.h"
#include "testing/gtest/include/gtest/gtest.h"

#include "keyczar/key_type.h"
#include "keyczar/keyset_file_reader.h"
#include "keyczar/keyset_file_writer.h"
#include "keyczar/openssl/rsa.h"
#include "keyczar/rsa_private_key.h"
#include "keyczar/rsa_public_key.h"

namespace keyczar {

class RSATest : public testing::Test {
 protected:
  virtual void SetUp() {
    PathService::Get(base::DIR_TEMP, &temp_path_);
    temp_path_ = temp_path_.AppendASCII("keyczar");
    file_util::CreateDirectory(temp_path_);

    PathService::Get(base::DIR_SOURCE_ROOT, &data_path_);
    data_path_ = data_path_.AppendASCII("keyczar");
    data_path_ = data_path_.AppendASCII("data");

    input_data_ = "This is some test data";
  }

  virtual void TearDown() {
    file_util::Delete(temp_path_, true);
  }

  // TODO(seb): add a dynamic_cast for each new rsa implementation.
  bool Equals(const RSAPrivateKey& lhs, const RSAPrivateKey& rhs) {
    const openssl::RSAOpenSSL* lhs_impl = dynamic_cast<openssl::RSAOpenSSL*>(
        lhs.rsa_impl());
    const openssl::RSAOpenSSL* rhs_impl = dynamic_cast<openssl::RSAOpenSSL*>(
        rhs.rsa_impl());
    if (!lhs_impl || !rhs_impl)
      return false;

    return lhs_impl->Equals(*rhs_impl);
  }

  // TODO(seb): add a dynamic_cast for each new rsa implementation.
  bool Equals(const RSAPublicKey& lhs, const RSAPublicKey& rhs) {
    const openssl::RSAOpenSSL* lhs_impl = dynamic_cast<openssl::RSAOpenSSL*>(
        lhs.rsa_impl());
    const openssl::RSAOpenSSL* rhs_impl = dynamic_cast<openssl::RSAOpenSSL*>(
        rhs.rsa_impl());
    if (!lhs_impl || !rhs_impl)
      return false;

    return lhs_impl->Equals(*rhs_impl);
  }

  // Loads private key from JSON file.
  scoped_refptr<RSAPrivateKey> LoadRSAPrivateKey(const FilePath& path,
                                                 int key_version) {
    KeysetFileReader reader(path);
    scoped_ptr<Value> value(reader.ReadKey(key_version));
    EXPECT_NE(static_cast<Value*>(NULL), value.get());
    scoped_refptr<RSAPrivateKey> private_key(
        RSAPrivateKey::CreateFromValue(*value));
    CHECK(private_key);
    return private_key;
  }

  // Loads public key from JSON file.
  scoped_refptr<RSAPublicKey> LoadRSAPublicKey(const FilePath& path,
                                               int key_version) {
    KeysetFileReader reader(path);
    scoped_ptr<Value> value(reader.ReadKey(key_version));
    EXPECT_NE(static_cast<Value*>(NULL), value.get());
    scoped_refptr<RSAPublicKey> public_key(RSAPublicKey::CreateFromValue(
                                               *value));
    CHECK(public_key);
    return public_key;
  }

  // Paths used in testing.
  FilePath temp_path_;
  FilePath data_path_;
  std::string input_data_;
};

TEST_F(RSATest, GeneratePrivateKeyAndPublicEncrypt) {
  scoped_ptr<KeyType> rsa_type(KeyType::Create("RSA_PRIV"));
  ASSERT_TRUE(rsa_type.get());
  int size = rsa_type->default_size();

  // Generates a new private key
  scoped_refptr<RSAPrivateKey> private_key(RSAPrivateKey::GenerateKey(size));
  ASSERT_TRUE(private_key.get());
  EXPECT_TRUE(private_key->GetType() &&
              private_key->GetType()->type() == KeyType::RSA_PRIV);

  // Attempts to encrypt and decrypt input data.
  std::string encrypted_data;
  EXPECT_TRUE(private_key->Encrypt(input_data_, &encrypted_data));
  EXPECT_EQ(static_cast<int>(encrypted_data.length()),
            Key::GetHeaderSize() + size / 8);
  std::string decrypted_data;
  EXPECT_TRUE(private_key->Decrypt(encrypted_data, &decrypted_data));
  EXPECT_EQ(input_data_, decrypted_data);
}

TEST_F(RSATest, GeneratePrivateKeyAndPrivateSign) {
  scoped_ptr<KeyType> rsa_type(KeyType::Create("RSA_PRIV"));
  ASSERT_TRUE(rsa_type.get());
  int size = rsa_type->default_size();

  // Generates a new private key.
  scoped_refptr<RSAPrivateKey> private_key(RSAPrivateKey::GenerateKey(size));
  ASSERT_TRUE(private_key.get());

  // Attempts to sign and verify input data.
  std::string signature;
  EXPECT_TRUE(private_key->Sign(input_data_, &signature));
  EXPECT_EQ(static_cast<int>(signature.length()), size / 8);
  EXPECT_TRUE(private_key->Verify(input_data_, signature));
}

TEST_F(RSATest, LoadPrivateKey) {
  FilePath rsa_path = data_path_.AppendASCII("rsa");
  scoped_refptr<RSAPrivateKey> private_key = LoadRSAPrivateKey(rsa_path, 1);

  // Attempts to encrypt and decrypt input data.
  std::string encrypted_data;
  EXPECT_TRUE(private_key->Encrypt(input_data_, &encrypted_data));
  std::string decrypted_data;
  EXPECT_TRUE(private_key->Decrypt(encrypted_data, &decrypted_data));
  EXPECT_EQ(input_data_, decrypted_data);
}

TEST_F(RSATest, LoadPublicKey) {
  FilePath rsa_private_path = data_path_.AppendASCII("rsa-sign");
  scoped_refptr<RSAPrivateKey> private_key = LoadRSAPrivateKey(rsa_private_path,
                                                               1);

  // Attempts to sign data with this private key.
  std::string signature;
  EXPECT_TRUE(private_key->Sign(input_data_, &signature));

  // Loads the associated public key
  FilePath rsa_public_path = data_path_.AppendASCII("rsa-sign.public");
  scoped_refptr<RSAPublicKey> public_key = LoadRSAPublicKey(rsa_public_path, 1);
  EXPECT_TRUE(public_key->GetType() &&
              public_key->GetType()->type() == KeyType::RSA_PUB);

  // Attempts to verify the signature with this public key.
  EXPECT_TRUE(public_key->Verify(input_data_, signature));
}

// Steps:
// 1- Loads private key
// 2- Dumps private key to temporary file
// 3- Loads this temporary file
// 3- Signs some data with this key
// 4- Then, exports the public part into a second temporary file
// 5- Loads this file and checks that the signature is valid
TEST_F(RSATest, LoadPrivateKeyDumpAndExport) {
  {
    FilePath rsa_path = data_path_.AppendASCII("rsa-sign");
    scoped_refptr<RSAPrivateKey> private_key = LoadRSAPrivateKey(rsa_path, 1);

    // Dumps private key into temporary path
    KeysetFileWriter writer(temp_path_);
    EXPECT_TRUE(writer.WriteKey(private_key->GetValue(), 1));
    ASSERT_TRUE(file_util::PathExists(temp_path_.Append("1")));
  }

  std::string signature;

  {
    // Loads the dumped key
    scoped_refptr<RSAPrivateKey> private_key = LoadRSAPrivateKey(temp_path_, 1);
    ASSERT_TRUE(private_key);

    // Attempts to sign data
    EXPECT_TRUE(private_key->Sign(input_data_, &signature));

    // Exports public key
    KeysetFileWriter writer(temp_path_);
    scoped_ptr<Value> private_key_value(private_key->GetPublicKeyValue());
    ASSERT_TRUE(private_key_value.get());
    EXPECT_TRUE(writer.WriteKey(private_key_value.get(), 2));
    ASSERT_TRUE(file_util::PathExists(temp_path_.Append("2")));
  }

  {
    // Loads public key
    scoped_refptr<RSAPublicKey> public_key = LoadRSAPublicKey(temp_path_, 2);
    ASSERT_TRUE(public_key);

    // Checks the signature
    EXPECT_TRUE(public_key->Verify(input_data_, signature));
  }
}

TEST_F(RSATest, CompareOutputHeader) {
  FilePath rsa_path = data_path_.AppendASCII("rsa");
  scoped_refptr<RSAPrivateKey> private_key = LoadRSAPrivateKey(rsa_path, 1);

  // Loads the encrypted data file and retrieve the output header
  std::string b64w_encrypted_data;
  EXPECT_TRUE(file_util::ReadFileToString(rsa_path.AppendASCII("1.out"),
                                          &b64w_encrypted_data));
  std::string encrypted_data;
  EXPECT_TRUE(Base64WDecode(b64w_encrypted_data, &encrypted_data));
  std::string header = encrypted_data.substr(0, Key::GetHeaderSize());

  // Compares headers
  std::string key_header;
  EXPECT_TRUE(private_key->Header(&key_header));
  EXPECT_EQ(header, key_header);
}

TEST_F(RSATest, CompareDecrypt) {
  FilePath rsa_path = data_path_.AppendASCII("rsa");
  scoped_refptr<RSAPrivateKey> private_key = LoadRSAPrivateKey(rsa_path, 1);

  // Try to decrypt corresponding data file
  std::string b64w_encrypted_data;
  EXPECT_TRUE(file_util::ReadFileToString(rsa_path.AppendASCII("1.out"),
                                          &b64w_encrypted_data));
  std::string encrypted_data;
  EXPECT_TRUE(Base64WDecode(b64w_encrypted_data, &encrypted_data));
  std::string decrypted_data;
  EXPECT_TRUE(private_key->Decrypt(encrypted_data, &decrypted_data));

  // Compares clear texts
  EXPECT_EQ(decrypted_data, input_data_);
}

TEST_F(RSATest, VerifyEncodedSignature) {
  FilePath rsa_sign_pub_path = data_path_.Append("rsa-sign.public");
  scoped_refptr<RSAPublicKey> public_key = LoadRSAPublicKey(rsa_sign_pub_path,
                                                            2);

  // Try to verify the signature file
  std::string b64w_signature;
  FilePath signature_file = data_path_.Append("rsa-sign");
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

TEST_F(RSATest, CompareOriginalAndDumpedPrivateKey) {
  FilePath rsa_path = data_path_.Append("rsa");
  scoped_refptr<RSAPrivateKey> original_key = LoadRSAPrivateKey(rsa_path, 1);

  // Dumps private key into temporary path
  KeysetFileWriter writer(temp_path_);
  EXPECT_TRUE(writer.WriteKey(original_key->GetValue(), 1));
  ASSERT_TRUE(file_util::PathExists(temp_path_.Append("1")));

  // Loads the dumped key
  scoped_refptr<RSAPrivateKey> dumped_key = LoadRSAPrivateKey(temp_path_, 1);
  ASSERT_TRUE(dumped_key);

  // Expect to be the equals
  EXPECT_TRUE(Equals(*original_key, *dumped_key));
}

TEST_F(RSATest, CompareOriginalAndExportedPublicKey) {
  FilePath rsa_path = data_path_.Append("rsa-sign");
  scoped_refptr<RSAPrivateKey> private_key = LoadRSAPrivateKey(rsa_path, 1);

  // Exports public key into temporary path
  KeysetFileWriter writer(temp_path_);
  scoped_ptr<Value> private_key_value(private_key->GetPublicKeyValue());
  ASSERT_TRUE(private_key_value.get());
  EXPECT_TRUE(writer.WriteKey(private_key_value.get(), 1));
  ASSERT_TRUE(file_util::PathExists(temp_path_.Append("1")));

  // Loads orginal public key
  FilePath rsa_path_pub = data_path_.Append("rsa-sign.public");
  scoped_refptr<RSAPublicKey> public_key = LoadRSAPublicKey(rsa_path_pub, 1);
  ASSERT_TRUE(public_key);

  // Loads the dumped key
  scoped_refptr<RSAPublicKey> dumped_key = LoadRSAPublicKey(temp_path_, 1);
  ASSERT_TRUE(dumped_key);

  // Expected to be the equals
  EXPECT_TRUE(Equals(*public_key, *dumped_key));
}

}  // namespace keyczar
