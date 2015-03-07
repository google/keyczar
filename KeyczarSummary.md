# Keyczar Summary #

## Key Generation ##
Key generation is done by the command line tool KeyczarTool. Some implementations like python support key generation programatically.

KeyczarTool also supports exporting public keys, importing keys, and performing key rotation related tasks.

## Supported Operations ##

| [Encrypt](OperationEncrypt.md)  |  [Decrypt](OperationDecrypt.md) | Authenticated Encryption, used to send messages |
|:--------------------------------|:--------------------------------|:------------------------------------------------|
| [Sign](OperationSign.md)        |  [Verify](OperationVerify.md)   | Used to generate a signature that provides Integrity on messages |
| [Attached Sign](OperationAttachedSign.md)  |  [Attached Verify](OperationAttachedVerify.md) | Attaches a signature to a message               |
| [Timeout Sign](OperationTimeoutSign.md) | [Timeout Verify](OperationTimeoutVerify.md) | Generates a signature that is only good for a certain period of time |
| [Unversioned Sign](OperationUnversionedSign.md) | [Unversioned Verify](OperationUnversionedVerify.md) | Generates a signature without keyczar headers   |
| [Sessions](OperationSessions.md) | [Sessions](OperationSessions.md) | Generates a symmetric key, encrypts the symmetric key, and then shares it and symmetric key encrypted data |
| [Signed Sessions](OperationSignedSessions.md) | [Signed Sessions](OperationSignedSessions.md) | Similar to [Sessions](OperationSessions.md), but the data is also signed. |

## Supported Algorithms ##
| **Algorithm Name** |  **C++ Key sizes**| **Java Key sizes**| **Python Key sizes** | **Notes** |
|:-------------------|:------------------|:------------------|:---------------------|:----------|
| AesKey             | **128**, 192, 256 | **128**, 192, 256 | **128**, 192, 256    |           |
| DsaPrivateKey      | 1024, **2048**, 3072 | **1024**          | **1024**             |           |
| DsaPublicKey       | 1024, **2048**, 3072 | **1024**          | **1024**             |           |
| HmacKey            |  **160**, 224, 256, 384, 512 | **256` * `**      | **256` * `**         | Please note that these 256 bit keys are used with SHA1 which does not improve its security beyond using SHA1 with a 160 bit key. C++ will also use 256 bit keys with SHA1 when running in compat mode.  |
| RsaPrivateKey      | 512, 768, 1024, **2048**, 3072, 4096 | **4096**, 2048, 1024 | **2048**, 4096, 1024, 768, 512 | SHA1 is used with all keysizes except in C++ running not in compat mode |
| RsaPublicKey       | 512, 768, 1024, **2048**, 3072, 4096 | **4096**, 2048, 1024 | **2048**, 4096, 1024, 768, 512 | SHA1 is used with all keysizes except in C++ running not in compat mode |

Bold numbers are the defaults.