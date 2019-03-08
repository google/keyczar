# Keyczar

*Important note:* Keyczar is deprecated.  The Keyczar developers recommend [Tink](https://github.com/google/tink).

## Introduction

Keyczar is an open source cryptographic toolkit designed to make it
easier and safer for developers to use cryptography in their
applications. Keyczar supports authentication and encryption with both
symmetric and asymmetric keys. Some features of Keyczar include:

- A simple API
- Key rotation and versioning
- Safe default algorithms, modes, and key lengths
- Automated generation of initialization vectors and ciphertext signatures
- Java, Python, and C++ implementations
- International support in Java

Keyczar was originally developed by members of the Google Security
Team and is released under an Apache 2.0 license.

## Quick Links

- [Known Security Issues](#known-security-issues)
- [Discussion Group](http://groups.google.com/group/keyczar-discuss)
- [Design Document (PDF)](https://github.com/google/keyczar/blob/wiki/keyczar05b.pdf)

## Why Keyczar?

Cryptography is easy to get wrong. Developers can choose improper
cipher modes, use obsolete algorithms, compose primitives in an unsafe
manner, or fail to anticipate the need for key rotation. Keyczar
abstracts some of these details by choosing safe defaults,
automatically tagging outputs with key version information, and
providing a simple programming interface.

Keyczar is designed to be open, extensible, and cross-platform
compatible. It is not intended to replace existing cryptographic
libraries like OpenSSL, PyCrypto, or the Java JCE, and in fact is
built on these libraries.

## An illustrative use case

Suppose an application needs to encrypt a URL parameter value with a
symmetric key. Normally, a developer would need to decide which
algorithm to use, the key length to use, the mode of operation, how to
handle initialization vectors, how to rotate keys, and how to sign
ciphertexts. Keyczar simplifies these choices. Using an existing
keyset, a Java developer would need to call the following:

```java
Crypter crypter = new Crypter("/path/to/your/keys");
String ciphertext = crypter.encrypt("Secret message");
```

Similarly a Python developer would call the following:

```python
crypter = Crypter.Read("/path/to/your/keys")
ciphertext = crypter.Encrypt("Secret message")
```

## Get involved

Interested in getting involved? We encourage open source developers to
contribute to the Keyczar project. Please join us on the Keyczar
project and subscribe to the Keyczar discussion group.


## Known Security Issues
The following section lists known security issues.

There are probably others that have not been identified.


### Use of SHA 1 and 1024 bit DSA
Keyczar uses 1024 bit DSA keys with SHA1. Both of these are considered weak by
current security standards.  However, it is not trivial to upgrade without breaking
backwards compatibility.


### Signed Session Encryption Re-signing
Keyczar signed session encryption does not include the key ID of the signing key inside
the encrypted plaintext. This makes it possible for an attacker to strip the signature
from a message, and re-sign it using their private key, making it look like they sent
the original message.


### DSA Signature Malleability
DSA signatures are basically two variable length ints. So some DSA signatures are shorter
than others.

There was a bug in KeyCzar (fixed
[here](https://github.com/google/keyczar/commit/fb019ba4c5ed7002b93e632e85c5bb95af860711))
which essentially padded (right padding with 0) all DSA signatures to their maximum length.

Some crypto libraries - including many JCE implementations - stop checking the signature
after finding both ints, which means that they will verify signature that have extra
data. This is why keyczar did not discover the extra data in DSA signatures.

However, this can be a problem for specific crypto applications that compute fingerprints
of data that includes a message and its signature. See the
[CVN](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-8275),
[OpenSSL's comments](https://www.openssl.org/news/vulnerabilities.html#2014-8275)
and [problem](and https://en.bitcoin.it/wiki/Transaction_Malleability)
this causes for BitCoint.

Some new JCE implementations are more strict - and will reject DSA signatures with extra
data. In order for older (improperly padded DSA signatures) to be acceptible even when
running KeyCzar on such new JCE implementations - the KeyCzar Java DSA verifier function
trims any extra data from the signature.

Note that this means you should not use this implementation for such applications - such as
bitcoin - without setting the "keyczar.strict\_dsa\_verification" system property.

As other underlying crypto libraries make this strict - it is probable that other language
implementations may have this issue.

