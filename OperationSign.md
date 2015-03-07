# Signing with Keyczar #
Generate digest signature of a message in SignatureFormat
## Java ##
Java will either sign the message as a WebSafeBase64 if input as a java string or will not do any encoding if passed in as a byte string. A byte string will be returned if a byte string is input and a WebSafeBase64 java string will be output if a java string is input.
```
Signer signer = new Signer("/path/to/your/keys");
String signature = signer.sign("Message with Integrity");
```

## Python ##
Python will take in a string of bytes and return a WebSafeBase64 encoded SignatureFormat value. There are no options for other encodings
```
signer = Signer.Read("/path/to/your/keys")
signature = signer.Sign("Message with Integrity")
```

## C++ ##
C++ will take in a string and return the WebSafeBase64 encoded SignatureFormat value. The Encoder can be set on the signer to None if no encoding is required.
```
keyczar::Keyczar* signer = keyczar::Signer::Read("/path/to/your/keys");
std::string input, signature;
input = "Message with Integrity";
if (!signer ||
    !signer->Sign(input, &signature)) {
  return 1;
}
```