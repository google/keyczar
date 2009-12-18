package org.keyczar;

import org.keyczar.Crypter;
import org.keyczar.annotations.Experimental;
import org.keyczar.enums.KeyType;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.i18n.Messages;
import org.keyczar.util.Util;

import java.nio.ByteBuffer;

/**
 * A hybrid encrypter will generate and encrypt a session key with a given
 * Encrytper. That session key will be used to encrypt arbitrary data. The
 * output will be signed with the given signer.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
@Experimental
public class HybridDecrypter {
  private final Crypter symmetricCrypter;
  private final Verifier verifier;
  private final byte[] sessionMaterial;
  
  public HybridDecrypter(Crypter crypter, Verifier verifier,
      byte[] sessionMaterial) throws KeyczarException {
    this.verifier = verifier;
    this.sessionMaterial = sessionMaterial;
    byte[] aesKeyBytes = crypter.decrypt(sessionMaterial);
    if (!KeyType.AES.isAcceptableSize(aesKeyBytes.length * 8)) {
      throw new KeyczarException(
          Messages.getString("HybridDecrypter.InvalidSessionKey"));
    }
    AesKey aesKey = AesKey.fromBytes(aesKeyBytes, false);
    ImportedKeyReader importedKeyReader = new ImportedKeyReader(aesKey);
    this.symmetricCrypter = new Crypter(importedKeyReader);
  }
  
  
  public byte[] decrypt(byte[] input) throws KeyczarException {
    byte[][] unpacked = Util.lenPrefixUnpack(input);
    if (unpacked.length != 2) {
      throw new KeyczarException(
          Messages.getString("HybridDecrypter.InvalidCiphertext"));      
    }
    byte[] ciphertext = unpacked[0];
    byte[] signature = unpacked[1];
    if (!verifier.verify(ByteBuffer.wrap(ciphertext),
        ByteBuffer.wrap(sessionMaterial), ByteBuffer.wrap(signature))) {
      throw new KeyczarException(
          Messages.getString("HybridDecrypter.InvalidCiphertext"));
    }
    return symmetricCrypter.decrypt(ciphertext);
  }
}
