# Timeout Signing with Keyczar #
Generate digest signature with expiration date as specified in TimeoutSignatureFormat
## Java ##
If the message is a byte [.md](.md), the returned signature will also be a byte array. If the message is a UTF8 string then java will return a java string containing the WebSafeBase64 encoding of the signature.
```
Signer signer = new TimeoutSigner("/path/to/your/keys");
String signature = signer.timeoutSign("Message with Integrity",1375095283);
```

## Python ##
Timeout Signature are not implemented in python. [Issue 10](https://code.google.com/p/keyczar/issues/detail?id=10).

## C++ ##

Timeout Signature are not implemented in C++. [Issue 128](https://code.google.com/p/keyczar/issues/detail?id=128)