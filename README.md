Introducing Keyczar
===================

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

Quick Links
-----------

- [Discussion Group](http://groups.google.com/group/keyczar-discuss)
- [Design Document (PDF)](http://keyczar.googlecode.com/files/keyczar05b.pdf)

Why Keyczar?
------------

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

An illustrative use case
------------------------

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
crypter = Crypter.Read("/path/to/your/keys");
ciphertext = crypter.Encrypt("Secret message");
```

Get involved
------------

Interested in getting involved? We encourage open source developers to
contribute to the Keyczar project. Please join us on the Keyczar
project and subscribe to the Keyczar discussion group.
