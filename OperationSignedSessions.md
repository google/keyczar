# Signed Session Encryption and Decryption with Keyczar #
Encrypts a 128 bit AES symmetric key using another keyczar key in session material and uses it to encrypt communication between two parties. The ciphertext is all signed by the passed in signing key.

The session material is encrypted json containing an AES key and a WebSafeBase64 nonce. Note that session material is not signed.
```
{
"key" : (byte_string),
"nonce" : (encoded_nonce)
}
```

## Java ##
Session material is WebSafeBase64 encoded. The returned ciphertext is not encoded. There are no other options for encoding.

Sender:
```
Encrypter keyEncrypter = new Encrypter("/path/to/your/keys");
Signer signer = new Signer("/path/to/signing/keys");
SignedSessionEncrypter crypter = new SignedSessionEncrypter(keyEncrypter, signer);
String sessionMaterial = crypter.newSession();
byte[] encryptedData = crypter.encrypt(data);
```

The sender now sends the sessionMaterial and encryptedData to the Reciever.

Reciever:
```
Crypter keyCrypter = new Crypter("/path/to/their/keys");
Verifier verifier = new Verifier("/path/to/verifing/keys");
SignedSessionDecrypter sessionCrypter = new SignedSessionDecrypter(keyCrypter, verifier, sessionMaterial);
byte[] decryptedData = sessionCrypter.decrypt(encryptedData);
```

## Python ##
All data is input as python strings. Session material is WebSafeBase64 encoded. There is no support for other encodings.

Sender:
```
key_encrypter = keyczar.Encrypter.Read("/path/to/encrypting/keys")
signer = keyczar.Signer.Read("/path/to/signing/keys")
crypter = keyczar.SignedSessionEncrypter(key_encrypter, signer)
encrypted_data = crypter.Encrypt(data)
session_material = crypter.session_material
```

The sender now sends the session\_material and encrypted\_data to the Reciever.

Reciever:
```
key_crypter = keyczar.Crypter.Read("/path/to/decrypting/keys")
verifier = keyczar.Verifier.Read("/path/to/verifing/keys")
session_decrypter = keyczar.SignedSessionDecrypter(key_crypter, verifier, session_material)
decrypted_data = sessionDecrypter.Decrypt(encrypted_data)
```

## C++ ##
After the message is attachedSign, the message is WebSafeBase64 encoded. This can be modified using the set\_encoding method on the SignedSessionEncrypter and SignedSessionDecrypter

Sender:std::string sessionMaterial, encryptedData;
keyczar::Encrypter* key_encrypter =
    keyczar::Encrypter::Read("/path/to/your/keys");
keyczar::Signer* signer =
    keyczar::Signer::Read("/path/to/signing/keys");
if (!key_encrypter || !signer) {
  return 1;
}
keyczar::SignedSessionEncrypter* crypter =
    SignedSessionEncrypter::NewSessionEncrypter(key_encrypter, signer);
if (!crypter ||
    !crypter->EncryptedSessionBlob(&session_material) ||
    !crypter->SessionEncrypt(data, &encrypted_data)) {
  return 1;
}

The sender now sends the session_material and encrypted_data to the Reciever.

Reciever:
{{{
std::string decrypted_data;
keyczar::Crypter key_crypter =
    new keyczar::Crypter::Read("/path/to/their/keys");
keyczar::Verifier verifier =
    new keyczar::Verifier::Read("/path/to/verifing/keys");
if (!key_crypter || !verifier) {
  return 1;
}
keyczar::SignedSessionDecrypter* crypter =
    keyczar::SignedSessionDecrypter::NewSessionDecrypter(
        key_crypter, verifier, session_material);
crypter.SessionDecrypt(encryptedData, &decrypted_data);
}}}```