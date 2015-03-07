# Encrypting with Keyczar #
Encrypt data to CiphertextFormat and possibly encoded as WebSafeBase64.
## Java ##
Java will take a byte array or a java string as input. If a byte array is passed in, a byte array is returned. If a java string is passed in it will be converted to a byte array and a WebSafeBase64 encoded string will be returned. The Crypter or Encrypter class can both be used for encryption depending on application.
```
Crypter crypter = new Crypter("/path/to/your/keys");
String ciphertext = crypter.encrypt("Secret message");
```

## Python ##
Python will only take strings of bytes as input. An encoding for the output can be specified with the encoding flag. The Crypter or Encrypter class can both be used for encryption depending on application.
```
crypter = Crypter.Read("/path/to/your/keys")
ciphertext = crypter.Encrypt("Secret message")
```

## C++ ##
C++ only takes strings as defined by std::string. These are equivalent to byte strings. A WebSafeBase64 encoded string will be returned. The type of encoding can be modified through the set\_encoding method on the crypter. The Crypter or Encrypter class can both be used for encryption depending on application.
```
std::string ciphertext, plaintext;
keyczar::Keyczar* crypter = keyczar::Crypter::Read("/path/to/your/keys");
if (!crypter ||
    !crypter->Encrypt("Secret message", &ciphertext)) {
  return 1;
}
```