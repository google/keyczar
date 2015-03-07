# Attached Signing with Keyczar #
Generate digest signature of a message and attaches to the message. Used for Signed Sessions. In format, ` Header.len(Message).Message.Sig(Message.Nonce.VersionBit) `
## Java ##
Java will take two byte arrays the message and the nonce. Then it will return a byte array in the format specified above. No support for WebSafeBase64
```
String input = "Message with Integrity";
String nonce = "Nonce";
Signer signer = new Signer("/path/to/your/keys");
String messsageWithSignature = signer.attachedSign(
    input.getBytes("UTF-8"), nonce.getBytes("UTF-8"));
```

## Python ##
Takes two strings as message and nonce. Then it returns a WebSafeBase64 encoded version of format specified above. Does not support unencoded messages.
```
signer = Signer.Read("/path/to/your/keys")
message_with_signature = signer.AttachedSign("Message with Integrity", "Nonce")
```

## C++ ##
C++ will take in two strings and return the WebSafeBase64 encoded value formatted as specified above. The Encoder can be set on the signer to None if no encoding is required.
```
keyczar::Keyczar* signer = keyczar::Signer::Read("/path/to/your/keys");
std::string input, message_with_signature, nonce, message;
input = "Message with Integrity";
nonce = "Nonce";
if (!signer ||
    !signer->AttachedSign(input, nonce, &message_with_signature)) {
  return 1;
}
```