# Key Purpose #

The KeyMetadata will specify a purpose for all keys within that set.
  * Decrypt and Encrypt
  * Encrypt Only
  * Sign and Verify
  * Verify

Keys cannot be used for any other purpose than what is defined by the KeyMetadata.

## JSON Representation ##

KeyPurpose values will be represented in JSON with one of the following strings:
  * "DECRYPT\_AND\_ENCRYPT"
  * "ENCRYPT"
  * "SIGN\_AND\_VERIFY"
  * "VERIFY"