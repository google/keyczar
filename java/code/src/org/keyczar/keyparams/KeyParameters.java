package org.keyczar.keyparams;

import org.keyczar.exceptions.KeyczarException;

/**
 * Interface for objects which provide key configuration parameters for key generation.
 * This base interface only provides one element, required by all keys: size.  Sub-interfaces
 * exist for specific key types that provide the configuration data they require.
 *
 * @author swillden
 */
public interface KeyParameters {

  /**
   * Returns desired key size, or -1 if unspecified.
   * @throws KeyczarException
   */
  public int getKeySize() throws KeyczarException;
}
