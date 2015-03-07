# Ciphertext Format #

All keyCzar ciphertext output contains an OutputHeader (which is a VersionByte and KeyHash). Additionally, it may contain an initialization vector, the raw ciphertext payload, and a Signature. The ciphertext output format for input M is as follows:

| OutputHeader | _Initialization Vector_ | Encrypt(M) | _Sign(preceding fields)_ |
|:-------------|:------------------------|:-----------|:-------------------------|

## AES Ciphertext Example ##

All keyCzar AesKey values have an attached HmacKey that is used for signing the output header, IV, and ciphertext. The current default CipherMode is CBC with PKCS#5 padding. So, for a 128-bit key ciphertext format will have the following form:

| OutputHeader | IV | Encrypt(M) | Sign(Preceding fields) |
|:-------------|:---|:-----------|:-----------------------|
| 5-byte H     | 16-byte IV | AES-CBC-PKCS5(IV, M) | HMAC-SHA1(H.IV.M)      |

(Let "." be a byte-wise concatenation operator.)

## RSA Ciphertext Example ##

keyCzar RsaPublicKey values do not have an attached authentication key and are used for RSA-OAEP encryption only. So, the output is just of the form:

| OutputHeader | Encrypt(M) |
|:-------------|:-----------|
| 5 bytes      | RSA-OAEP(M) |