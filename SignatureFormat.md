# Signature Format v0.6b #

All keyCzar signatures are preceded with an OutputHeader (consisting of a VersionByte and KeyHash). An input message M will be terminated with the VersionByte and signed.

| OutputHeader | Sign(M . VersionByte) |
|:-------------|:----------------------|

(Let "." be a byte-wise concatenation operator.)

# Signature Format v0.5b #

All keyCzar signatures are preceded with an OutputHeader (consisting of a VersionByte and KeyHash). Given an input message M, both the OutputHeader and M will be signed together:

| OutputHeader | Sign(OutputHeader . M) |
|:-------------|:-----------------------|

(Let "." be a byte-wise concatenation operator.)