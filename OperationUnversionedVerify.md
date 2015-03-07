# Unsigned Verifying with Keyczar #
Verify raw digest signature of a message. Both the UnversionedSigner and UnversionedVerifier classes can be used for verification. Will attempt to try all keys in keyset until one works. Returns a boolean.
## Java ##
Inputs must be either a UTF8 message and WebSafeBase64 encoded java string or both unencoded byte arrays.
```
UnversionedSigner signer = new UnversionedSigner("/path/to/your/keys");
String signature = signer.sign("Message with Integrity");
boolean verified = signer.verify("Message with Integrity", signature);
```

## Python ##
Python will take in a string of bytes and a WebSafeBase64 encoded signature.
```
signer = UnversionedSigner.Read("/path/to/your/keys")
signature = signer.Sign("Message with Integrity")
verified = signer.Verify("Message with Integrity", signature)
```

## C++ ##
C++ will take in a string and the WebSafeBase64 encoded raw signature. The Encoder can be set on the verifier to NONE for a string of bytes instead of an encoded signature.
```
std::string input, signature;
input = "Message with Integrity";
keyczar::Keyczar* signer =
    keyczar::UnversionedSigner::Read("/path/to/your/keys");
if (!signer ||
    !signer->Sign(input, &signature)) {
  return 1;
}
bool verified = signer->Verify(input, signature);
```