# Decrypting with Keyczar #
Decrypt data formatted as CiphertextFormat and possibly encoded as WebSafeBase64.
## Java ##
Java will either decode the ciphertext as a WebSafeBase64 if input as a java string or will not do any decoding if passed in as a byte string. A byte string will be returned if a byte string is input and a java string will be output if a java string is input.
```
Crypter crypter = new Crypter("/path/to/your/keys");
String ciphertext = crypter.encrypt("Secret message");
String plaintext = crypter.decrypt(ciphertext);
```

## Python ##
Python will only take strings of bytes as input. It expects it to be encoded in WebSafeBase64, but this can be changed by setting the decoder. It will return the plaintext as a python string.
```
crypter = Crypter.Read("/path/to/your/keys")
ciphertext = crypter.Encrypt("Secret message")
plaintext = crypter.Decrypt(ciphertext)
```

## C++ ##
C++ expects a WebSafeBase64 encoded ciphertext string by default. The type of encoding can be modified through the set\_encoding method on the crypter to take a byte string. It returns a byte string.
```
std::string ciphertext, plaintext;
keyczar::Keyczar* crypter = keyczar::Crypter::Read("/path/to/your/keys");
if (!crypter ||
    !crypter->Encrypt("Secret message", &ciphertext)) {
  return 1;
}
if (!crypter->Decrypt(ciphertext, &plaintext)) return 1;
```