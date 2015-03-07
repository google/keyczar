# Timeout Signing with Keyczar #
Verify digest signature with expiration date as specified in TimeoutSignatureFormat
## Java ##
Can take either a two byte arrays or a UTF8 Java string and a WebSafeBase64 encoded signature.
```
Signer signer = new TimeoutSigner("/path/to/your/keys");
String signature = signer.timeoutSign("Message with Integrity",1375095283);
boolean verified = signer.verify("Message with Integrity", signature);
```

## Python ##
Timeout Signature are not implemented in python. [Issue 10](https://code.google.com/p/keyczar/issues/detail?id=10).

## C++ ##

Timeout Signature are not implemented in C++. [Issue 128](https://code.google.com/p/keyczar/issues/detail?id=128)