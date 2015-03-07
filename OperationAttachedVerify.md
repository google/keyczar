# Attached Verify with Keyczar #
Verifies attached siganture of message in the format output by attached sign, ` Header.len(Message).Message.Sig(Message.Nonce.VersionBit) `
## Java ##
Java will take two byte arrays the signed message and the nonce. Then it will return a boolean. No support for WebSafeBase64
```
String input = "Message with Integrity";
String nonce = "Nonce";
Signer signer = new Signer("/path/to/your/keys");
byte[] messsageWithSignature = signer.attachedSign(
    input.getBytes("UTF-8"), nonce.getBytes("UTF-8"));
boolean verified = signer.attachedVerify(
    messageWithSignature, nonce.getBytes("UTF-8"));
```

## Python ##
Takes WebSafeBase64 encoded message with signature and nonce. Then it returns a version of format specified above. Does not support unencoded messages with signatures.
```
signer = Signer.Read("/path/to/your/keys")
message_with_signature = signer.AttachedSign("Message with Integrity", "Nonce")
verified = signer.AttachedVerify(message_with_signature, "Nonce")
```

## C++ ##
C++ will take in WebSafeBase64 encoded message with signature and nonce and return the result of the verification. The Encoder can be set on the signer to None if no encoding is required.
```
keyczar::Keyczar* signer = keyczar::Signer::Read("/path/to/your/keys");
std::string input, message_with_signature, nonce, message;
input = "Message with Integrity";
nonce = "Nonce";
if (!signer ||
    !signer->AttachedSign(input, nonce, &message_with_signature)) {
  return 1;
}
bool verified = signer->AttachedVerify(message_with_signature, nonce, &message);
```