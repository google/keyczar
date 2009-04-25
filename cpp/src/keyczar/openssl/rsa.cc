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
#include "keyczar/openssl/rsa.h"

#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <stdio.h>

#include "base/file_util.h"
#include "base/logging.h"

namespace {

typedef scoped_ptr_malloc<
    BIGNUM, keyczar::openssl::OSSLDestroyer<BIGNUM, BN_free> > ScopedBIGNUM;

}  // namespace

namespace keyczar {

namespace openssl {

// static
RSAOpenSSL* RSAOpenSSL::Create(const RSAIntermediateKey& key,
                               bool private_key) {
  ScopedRSAKey rsa_key(RSA_new());
  if (rsa_key.get() == NULL) {
    PrintOSSLErrors();
    return NULL;
  }

  // n
  rsa_key->n = BN_bin2bn(reinterpret_cast<unsigned char*>(
                             const_cast<char*>(key.n.data())),
                         key.n.length(), NULL);
  if (rsa_key->n == NULL)
    return NULL;

  // e
  rsa_key->e = BN_bin2bn(reinterpret_cast<unsigned char*>(
                             const_cast<char*>(key.e.data())),
                         key.e.length(), NULL);
  if (rsa_key->e == NULL)
    return NULL;

  if (!private_key)
    return new RSAOpenSSL(rsa_key.release(), private_key);

  // d
  rsa_key->d = BN_bin2bn(reinterpret_cast<unsigned char*>(
                             const_cast<char*>(key.d.data())),
                         key.d.length(), NULL);
  if (rsa_key->d == NULL)
    return NULL;

  // p
  rsa_key->p = BN_bin2bn(reinterpret_cast<unsigned char*>(
                             const_cast<char*>(key.p.data())),
                         key.p.length(), NULL);
  if (rsa_key->p == NULL)
    return NULL;

  // q
  rsa_key->q = BN_bin2bn(reinterpret_cast<unsigned char*>(
                             const_cast<char*>(key.q.data())),
                         key.q.length(), NULL);
  if (rsa_key->q == NULL)
    return NULL;

  // dmp1
  rsa_key->dmp1 = BN_bin2bn(reinterpret_cast<unsigned char*>(
                                const_cast<char*>(key.dmp1.data())),
                            key.dmp1.length(), NULL);
  if (rsa_key->dmp1 == NULL)
    return NULL;

  // dmq1
  rsa_key->dmq1 = BN_bin2bn(reinterpret_cast<unsigned char*>(
                                const_cast<char*>(key.dmq1.data())),
                            key.dmq1.length(), NULL);
  if (rsa_key->dmq1 == NULL)
    return NULL;

  // iqmp
  rsa_key->iqmp = BN_bin2bn(reinterpret_cast<unsigned char*>(
                                const_cast<char*>(key.iqmp.data())),
                            key.iqmp.length(), NULL);
  if (rsa_key->iqmp == NULL)
    return NULL;

  // Check private key
  if (!RSA_check_key(rsa_key.get()))
    return NULL;

  return new RSAOpenSSL(rsa_key.release(), private_key);
}

// static
RSAOpenSSL* RSAOpenSSL::GenerateKey(int size) {
  ScopedRSAKey rsa_key(RSA_new());
  if (rsa_key.get() == NULL) {
    PrintOSSLErrors();
    return NULL;
  }

  ScopedBIGNUM public_exponent(BN_new());
  if (public_exponent.get() == NULL) {
    PrintOSSLErrors();
    return NULL;
  }

  if (!BN_set_word(public_exponent.get(), RSA_F4)) {
    PrintOSSLErrors();
    return NULL;
  }

  if (!RSA_generate_key_ex(rsa_key.get(), size, public_exponent.get(), NULL)) {
    PrintOSSLErrors();
    return NULL;
  }

  // Check private key
  if (!RSA_check_key(rsa_key.get()))
    return NULL;

  return new RSAOpenSSL(rsa_key.release(),
                        true /* private_key */);
}

bool RSAOpenSSL::GetAttributes(RSAIntermediateKey* key) {
  if (key == NULL || key_.get() == NULL)
    return false;

  if (!private_key_ || !key_->d || !key_->p || !key_->q || !key_->dmp1 ||
      !key_->dmq1 || !key_->iqmp)
    return false;

  if (!GetPublicAttributes(key))
    return false;

  // d
  int num_d = BN_num_bytes(key_->d);
  unsigned char d[num_d];
  if (BN_bn2bin(key_->d, d) != num_d) {
    PrintOSSLErrors();
    return false;
  }
  key->d.assign(reinterpret_cast<char*>(d), num_d);

  // p
  int num_p = BN_num_bytes(key_->p);
  unsigned char p[num_p];
  if (BN_bn2bin(key_->p, p) != num_p) {
    PrintOSSLErrors();
    return false;
  }
  key->p.assign(reinterpret_cast<char*>(p), num_p);

  // q
  int num_q = BN_num_bytes(key_->q);
  unsigned char q[num_q];
  if (BN_bn2bin(key_->q, q) != num_q) {
    PrintOSSLErrors();
    return false;
  }
  key->q.assign(reinterpret_cast<char*>(q), num_q);

  // dmp1
  int num_dmp1 = BN_num_bytes(key_->dmp1);
  unsigned char dmp1[num_dmp1];
  if (BN_bn2bin(key_->dmp1, dmp1) != num_dmp1) {
    PrintOSSLErrors();
    return false;
  }
  key->dmp1.assign(reinterpret_cast<char*>(dmp1), num_dmp1);

  // dmq1
  int num_dmq1 = BN_num_bytes(key_->dmq1);
  unsigned char dmq1[num_dmq1];
  if (BN_bn2bin(key_->dmq1, dmq1) != num_dmq1) {
    PrintOSSLErrors();
    return false;
  }
  key->dmq1.assign(reinterpret_cast<char*>(dmq1), num_dmq1);

  // iqmp
  int num_iqmp = BN_num_bytes(key_->iqmp);
  unsigned char iqmp[num_iqmp];
  if (BN_bn2bin(key_->iqmp, iqmp) != num_iqmp) {
    PrintOSSLErrors();
    return false;
  }
  key->iqmp.assign(reinterpret_cast<char*>(iqmp), num_iqmp);

  return true;
}

bool RSAOpenSSL::GetPublicAttributes(RSAIntermediateKey* key) {
  if (key == NULL || key_.get() == NULL)
    return false;

  if (!key_->n || !key_->e)
    return false;

  // n
  int num_n = BN_num_bytes(key_->n);
  unsigned char n[num_n];
  if (BN_bn2bin(key_->n, n) != num_n) {
    PrintOSSLErrors();
    return false;
  }
  key->n.assign(reinterpret_cast<char*>(n), num_n);

  // e
  int num_e = BN_num_bytes(key_->e);
  unsigned char e[num_e];
  if (BN_bn2bin(key_->e, e) != num_e) {
    PrintOSSLErrors();
    return false;
  }
  key->e.assign(reinterpret_cast<char*>(e), num_e);

  return true;
}

bool RSAOpenSSL::WriteKeyToPEMFile(const std::string& path) {
  if (key_.get() == NULL)
    return false;

  FILE* dest_file = file_util::OpenFile(path, "w+");
  if (dest_file == NULL)
    return false;

  int return_value = 0;
  if (private_key_)
    return_value = PEM_write_RSAPrivateKey(dest_file, key_.get(), NULL,
                                           NULL, 0, 0, NULL);
  else
    return_value = PEM_write_RSAPublicKey(dest_file, key_.get());

  if (!return_value)
    return false;
  return true;
}

bool RSAOpenSSL::Sign(const std::string& message_digest,
                      std::string* signature) const {
  if (key_.get() == NULL || signature == NULL || !private_key_)
    return false;

  int rsa_size = RSA_size(key_.get());
  unsigned char signature_buffer[rsa_size];
  uint32 signature_length = 0;

  if (RSA_sign(NID_sha1,
               reinterpret_cast<unsigned char*>(
                   const_cast<char*>(message_digest.data())),
               message_digest.length(),
               signature_buffer,
               &signature_length,
               key_.get()) != 1) {
    PrintOSSLErrors();
    return false;
  }

  signature->assign(reinterpret_cast<char*>(signature_buffer),
                    signature_length);
  return true;
}

bool RSAOpenSSL::Verify(const std::string& message_digest,
                        const std::string& signature) const {
  if (key_.get() == NULL)
    return false;

  if (RSA_verify(NID_sha1,
                 reinterpret_cast<unsigned char*>(
                     const_cast<char*>(message_digest.data())),
                 message_digest.length(),
                 reinterpret_cast<unsigned char*>(
                     const_cast<char*>(signature.data())),
                 signature.length(),
                 key_.get()) != 1) {
    PrintOSSLErrors();
    return false;
  }
  return true;
}

bool RSAOpenSSL::Encrypt(const std::string& data,
                         std::string* encrypted) const {
  if (key_.get() == NULL || encrypted == NULL)
    return false;

  uint32 rsa_size = RSA_size(key_.get());

  if (data.length() >= rsa_size - 41) {
    LOG(WARNING) <<
        "Too long length of input data must be inferior to key size - 41.";
    return false;
  }

  unsigned char encrypted_buffer[rsa_size];
  int encrypted_len = RSA_public_encrypt(data.length(),
                                         reinterpret_cast<unsigned char*>(
                                             const_cast<char*>(data.data())),
                                         encrypted_buffer,
                                         key_.get(),
                                         RSA_PKCS1_OAEP_PADDING);
  if (encrypted_len == -1) {
    PrintOSSLErrors();
    return false;
  }
  DCHECK(encrypted_len == static_cast<int>(rsa_size));

  encrypted->assign(reinterpret_cast<char*>(encrypted_buffer), rsa_size);
  return true;
}

bool RSAOpenSSL::Decrypt(const std::string& encrypted,
                         std::string* data) const {
  if (key_.get() == NULL || data == NULL || !private_key_)
    return false;

  int rsa_size = RSA_size(key_.get());
  unsigned char data_buffer[rsa_size];

  int data_len = RSA_private_decrypt(encrypted.length(),
                                     reinterpret_cast<unsigned char*>(
                                         const_cast<char*>(encrypted.data())),
                                     data_buffer,
                                     key_.get(),
                                     RSA_PKCS1_OAEP_PADDING);
  if (data_len == -1) {
    PrintOSSLErrors();
    return false;
  }
  DCHECK(data_len < rsa_size - 41);

  data->assign(reinterpret_cast<char*>(data_buffer), data_len);
  return true;
}

bool RSAOpenSSL::Equals(const RSAOpenSSL& rhs) const {
  if (private_key() != rhs.private_key())
    return false;

  const RSA* key_rhs = rhs.key();

  if (BN_cmp(key_->n, key_rhs->n) != 0 || BN_cmp(key_->e, key_rhs->e) != 0)
    return false;

  if (!private_key())
    return true;

  if (BN_cmp(key_->d, key_rhs->d) != 0 ||
      BN_cmp(key_->p, key_rhs->p) != 0 ||
      BN_cmp(key_->q, key_rhs->q) != 0 ||
      BN_cmp(key_->dmp1, key_rhs->dmp1) != 0 ||
      BN_cmp(key_->dmq1, key_rhs->dmq1) != 0 ||
      BN_cmp(key_->iqmp, key_rhs->iqmp) != 0)
    return false;

  return true;
}

}  // namespace openssl

}  // namespace keyczar
