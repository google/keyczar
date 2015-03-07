# Keyczar Non-Goals #

Keyczar is not intended to:
  * Replace crypto libraries like OpenSSL, PyCrypto or the Java JCE. In fact, it uses these for underlying crypto operations, and could easily use others.
  * Be backwards compatible (at least, not yet). Keyczar is not designed to work with legacy crypto output formats. It's a fresh start that is designed to be simple and extensible.
  * Serve keys or act as a PKI. Keyczar is essentially a library, and doesn't actually serve keys or certificates. Keyczar keys are just flat files in a directory.


Essentially, by hiding some implementation details from the programmer, Keyczar sacrifices some flexibility. Some things Keyczar will work for, but not as well as other options. For example:
  * Encrypting very short blobs of data. Since Keyczar automatically adds version data, IVs, padding, and signatures, each symmetric ciphertext may have 40-50 bytes of overhead. Future developments can allow it to encrypt small blobs of data without adding as much overhead.
  * Encrypting huge files. While there is no reason Keyczar cannot encrypt huge blobs of data, its current API is better suited for plaintext in memory. Again, future API changes can make it more file friendly.