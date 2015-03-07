# Verifying with Keyczar #
Verify digest signature of a message in SignatureFormat. Both the Signer and Verifier classes can be used for verification. Returns a boolean.
## Java ##
Inputs must be either a UTF8 message and WebSafeBase64 encoded java string or both unencoded byte arrays.
```
Signer signer = new Signer("/path/to/your/keys");
String signature = signer.sign("Message with Integrity");
boolean verified = signer.verify("Message with Integrity", signature);
```

## Python ##
Python will take in a string of bytes and a WebSafeBase64 encoded SignatureFormat signature.
```
signer = keyczar.Signer.Read("/path/to/your/keys")
signature = signer.Sign("Message with Integrity")
verified = signer.Verify("Message with Integrity", signature)
```

## C++ ##
C++ will take in a string and the WebSafeBase64 encoded SignatureFormat value. The Encoder can be set on the verifier to NONE for a string of bytes instead of an encoded signature.
```
keyczar::Keyczar* signer = keyczar::Signer::Read("/path/to/your/keys");
std::string input, signature;
input = "Message with Integrity";
if (!signer ||
    !signer->Sign(input, &signature)) {
  return 1;
}
bool verified = signer->Verify(input, signature);
```