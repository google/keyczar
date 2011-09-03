// Copyright 2011 Google Inc. All Rights Reserved.
//
// Author: Shawn Willden (swillden@google.com)
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
#include <stdio.h>

#include <testing/gtest/include/gtest/gtest.h>

#include <keyczar/keyczar_test.h>
#include <keyczar/session.h>

namespace keyczar {

class SessionTest : public KeyczarTest {
 protected:
  virtual void SetUp() {
    KeyczarTest::SetUp();  // Sets up paths and data.
  }

  // Common test methods
  void RoundTripWithSpecificKeys(const std::string& encrypt_path,
                                 const std::string& sign_path) const;
};

TEST_F(SessionTest, RoundTripWithVariousKeyTypes) {
  std::string enc_types[] = { "aes", "rsa" };
  std::string sig_types[] = { "hmac", "dsa", "rsa-sign", "ecdsa"};

  for (int i = 0; i < sizeof(enc_types) / sizeof(enc_types[0]); ++i) {
    for (int j = 0; j < sizeof(sig_types) / sizeof(sig_types[0]); ++j) {
       RoundTripWithSpecificKeys(enc_types[i], sig_types[j]);
    }
  }
}

void SessionTest::RoundTripWithSpecificKeys(
    const std::string& encrypt_path,
    const std::string& sign_path) const {
  const FilePath aes_path = data_path_.Append(encrypt_path);
  scoped_ptr<Crypter> crypter(Crypter::Read(aes_path));
  ASSERT_TRUE(crypter.get());

  const FilePath hmac_path = data_path_.Append(sign_path);
  scoped_ptr<Signer> signerVerifier(Signer::Read(hmac_path));
  ASSERT_TRUE(signerVerifier.get());

  scoped_ptr<SignedSessionEncrypter> encrypter(
      SignedSessionEncrypter::NewSessionEncrypter(crypter.release(),
                                                  signerVerifier.release()));
  ASSERT_TRUE(encrypter.get());

  std::string session_material = encrypter->EncryptedSessionBlob();
  ASSERT_GT(session_material.size(), 0);

  std::string ciphertext = encrypter->SessionEncrypt(input_data_);
  ASSERT_GT(ciphertext.size(), 0);

  crypter.reset(Crypter::Read(aes_path));
  ASSERT_TRUE(crypter.get());
  signerVerifier.reset(Signer::Read(hmac_path));
  ASSERT_TRUE(signerVerifier.get());

  scoped_ptr<SignedSessionDecrypter> decrypter(
      SignedSessionDecrypter::NewSessionDecrypter(crypter.release(),
                                                  signerVerifier.release(),
                                                  session_material));
  ASSERT_TRUE(decrypter.get());

  std::string plaintext = decrypter->SessionDecrypt(ciphertext);
  ASSERT_EQ(input_data_, plaintext);
}

} // namespace keyzcar
