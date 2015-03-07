# Session Encryption and Decryption with Keyczar #
Encrypts a symmetric key using another keyczar key and uses it to communicate across a session
## Java ##
All data is stored as byte arrays. There is no support for encoding.

Sender:
```
Encrypter keyEncrypter = new Encrypter("/path/to/your/keys");
SessionCrypter crypter = new SessionCrypter(keyEncrypter);
byte[] encryptedData = crypter.encrypt(data);
byte[] sessionMaterial = crypter.getSessionMaterial();
```

The sender now sends the sessionMaterial and encryptedData to the Reciever.

Reciever:
```
Crypter keyCrypter = new Crypter("/path/to/their/keys");
SessionCrypter sessionCrypter = new SessionCrypter(keyCrypter, sessionMaterial);
byte[] decryptedData = sessionCrypter.decrypt(encryptedData);
```

## Python ##
All data is input as python strings and ciphertext and session material is WebSafeBase64 encoded. There is no support for other encodings.

Sender:
```
key_encrypter = Encrypter.Read("/path/to/your/keys")
crypter = SessionEncrypter(key_encrypter)
encrypted_data = crypter.Encrypt(data)
session_material = crypter.getSessionMaterial()
```

The sender now sends the sessionMaterial and encrypted\_data to the Reciever.

Reciever:
```
key_crypter = Crypter.Read("/path/to/their/keys")
session_decrypter = SessionDecrypter(key_crypter, session_material)
decryptedData = session_decrypter.Decrypt(encrypted_data)
```

## C++ ##
C++ Sessions are incompatible with Java and Python Sessions. [Issue 131](https://code.google.com/p/keyczar/issues/detail?id=131)