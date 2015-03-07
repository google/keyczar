# Keyczar #

Keyczar is an open source cryptographic toolkit designed to make it easier and safer for developers to use cryptography in their applications. Keyczar supports authentication and encryption with both symmetric and asymmetric keys. Some features of Keyczar include:

  * A simple API
  * Key rotation and versioning
  * Safe default algorithms, modes, and key lengths
  * Automated generation of initialization vectors and ciphertext signatures
  * Java, Python, and C++ implementations

## Why Keyczar? ##

Cryptography is easy to get wrong. Developers can often choose the wrong cipher mode, use obsolete algorithms, compose primitives in an unsafe manner, or fail to anticipate the need for key rotation. Keyczar abstracts some of these details by choosing safe defaults, automatically tagging outputs with key version information, and providing a simple interface.

Keyczar is designed to be open, extensible, and cross-platform compatible. It is not intended to replace existing cryptographic libraries like OpenSSL, PyCrypto, or the Java JCE, and in fact is built on these libraries.

## An illustrative use case ##

Suppose an application needs to encrypt a URL parameter value with a symmetric key. Normally, a developer would need to decide which algorithm to use, the key length to use, the mode of operation, how to handle initialization vectors, how to rotate keys, and how to sign ciphertexts. Keyczar simplifies these choices. Using an existing keyset, a Java developer would just need to call the following:
```
	Crypter crypter = new Crypter("/path/to/your/keys");
	String ciphertext = crypter.encrypt("Secret message");
```

Similarly a Python developer would just call the following:
```
	crypter = Crypter.Read("/path/to/your/keys");
	ciphertext = crypter.Encrypt("Secret message");
```

An example in C++:
```
        keyczar::Keyczar* crypter = keyczar::Encrypter::Read(location);
        if (!crypter) return 1;
        std::string ciphertext;
        bool result = crypter->Encrypt(input, &ciphertext);
```

## For More Information ##

Please see the [Wiki](https://code.google.com/p/keyczar/wiki/KeyczarPhilosophy), [design documents](http://keyczar.googlecode.com/files/keyczar05b.pdf), [JavaDocs](http://www.keyczar.org/javadocs/index.html), and [PyDocs](http://www.keyczar.org/pydocs/index.html) for more information. Keyczar's unit test cases are also good examples of typical usage.

## For Developers ##

Git:
```
git clone https://code.google.com/p/keyczar/
```

## Caveats ##

Keyczar sacrifices some flexibility in favor of safety and ease of use. Protecting developers from mistakes and handling details for them may also hide useful underlying features. Please see the NonGoals wiki page for a description of things that Keyczar is not.