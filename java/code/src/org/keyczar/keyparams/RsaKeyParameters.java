package org.keyczar.keyparams;

import org.keyczar.enums.RsaPadding;
import org.keyczar.exceptions.KeyczarException;

/**
 * Interface for objects which provide configuration information for RSA key generation.
 *
 * @author swillden@google.com (Shawn Willden)
 */
public interface RsaKeyParameters extends KeyParameters {

  /**
   * Returns the padding mode that should be used by the generated key to generate ciphertexts,
   * or null if unspecified.
   */
  public RsaPadding getRsaPadding() throws KeyczarException;
}
