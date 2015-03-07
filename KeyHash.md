# Key Hash #

The KeyHash is a SHA-1 hash of a key's byte representation. This hash will be truncated to the first 4-bytes and used to identify a key. The remaining 16 bytes will be discarded. The KeyHash allows Keyczar to tell which key produced a signature or ciphertext.

The components used to calculate the Key hash can be found on each of the algorithm pages

### Example Truncated SHA-1 Values ###

The truncated 4-byte truncated SHA-1 values:

  * The 4-byte truncated hash of ` SHA-1("") = da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709 ` encoded in hexadecimal is **` da39a3ee `**.
  * The truncated hash of ` SHA-1("The quick brown fox jumps over the lazy dog") = 2fd4e1c6 7a2d28fc ed849ee1 bb76e739 1b93eb12 ` is **` 2fd4e1c6 `**.

### Why SHA-1? ###

It's widespread and fast. We are not concerned about attacks against its collision resistance. If there is an attack against SHA-1's one-wayness, then information on key material could theoretically be leaked.

### What about ID collisions? ###

Due to the birthday paradox, 4-byte key ID collisions will likely appear in sets of tens of thousands of keys. However, even for sets of billions of keys, is is highly unlikely that more than 30-40 keys collide on the same 4-byte identifier. Keyczar implementations will handle collisions by exhaustively trying all keys with the same key ID, perhaps using some other data like creation time or last usage to prioritize the search order.