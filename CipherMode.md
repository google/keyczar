# Cipher Mode #

Keyczar supports four modes of operation:
  * **CBC**: Cipher block chaining with initial value (IV), PKCS5Padding
  * **CTR**: Counter with IV, no padding. **Currently not supported**
  * **ECB**: Electronic code book, no IV, no padding. **Currently not supported**
  * **DET-CBC**: CBC, no IV, PKCS5Padding. **Currently not supported**