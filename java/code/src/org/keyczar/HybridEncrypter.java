package org.keyczar;

import org.keyczar.Crypter;
import org.keyczar.Encrypter;
import org.keyczar.Signer;
import org.keyczar.annotations.Experimental;
import org.keyczar.enums.KeyType;
import org.keyczar.exceptions.KeyczarException;
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
public class HybridEncrypter {
  private final Crypter symmetricCrypter;
  private final Signer signer; 
  private final byte[] sessionMaterial;

  /**
   * Create a hybrid encrypter. This will generate a session key and encrypt
   * it with the given Encrypter. That session key will be used to encrypt
   * arbitrary data. That output will be signed with the given signer.
   *
   * @param encrypter The encrypter used to encrypt session keys
   * @param signer The signer to sign session ciphertexts
   * @throws KeyczarException If there is an error instantiating a Crypter 
   */
  public HybridEncrypter(Encrypter encrypter, Signer signer)
      throws KeyczarException {
    this.signer = signer;
    // Using minimum acceptable AES key size 
    byte[] aesKeyBytes = Util.rand(KeyType.AES.getAcceptableSizes().get(0) / 8);
    AesKey aesKey = AesKey.fromBytes(aesKeyBytes, false);
    ImportedKeyReader importedKeyReader = new ImportedKeyReader(aesKey);
    this.symmetricCrypter = new Crypter(importedKeyReader);
    this.sessionMaterial = encrypter.encrypt(aesKeyBytes);
  }

  public byte[] encrypt(byte[] plaintext) throws KeyczarException {
    byte[] ciphertext = symmetricCrypter.encrypt(plaintext);
    byte[] signature = new byte[signer.digestSize()];
    ByteBuffer signatureBuffer = ByteBuffer.wrap(signature);
    
    // Sign both the symmetric ciphertext and the session material
    signer.sign(ByteBuffer.wrap(ciphertext),
        ByteBuffer.wrap(sessionMaterial), 0, ByteBuffer.wrap(signature));
    return Util.lenPrefixPack(ciphertext, signature);
  }

  /**
   * @return An encryption of a session key and a nonce
   * @throws KeyczarException If an encryption error occurred
   */
  public byte[] getSessionMaterial() throws KeyczarException {
    return this.sessionMaterial;
  }
}
