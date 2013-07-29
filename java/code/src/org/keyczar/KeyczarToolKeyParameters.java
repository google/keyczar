package org.keyczar;

import org.keyczar.enums.Flag;
import org.keyczar.enums.RsaPadding;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.i18n.Messages;
import org.keyczar.keyparams.AesKeyParameters;
import org.keyczar.keyparams.RsaKeyParameters;

import java.util.HashMap;

/**
 * A key configuration class used by KeyczarTool to provide configuration data for
 * key generation.  It extracts provided configuration parameters from command-line
 * flags, handles providing default values where possible and reports errors and
 * warnings for missing required values or provided invalid or sub-optimal values.
 *
 * @author swillden@google.com (Shawn Willden)
 */
public class KeyczarToolKeyParameters implements AesKeyParameters, RsaKeyParameters {

  private final HashMap<Flag, String> flagMap;

  public KeyczarToolKeyParameters(HashMap<Flag, String> flagMap) {
    this.flagMap = flagMap;
  }

  @Override
  public RsaPadding getRsaPadding() throws KeyczarException {
    String paddingFlag = flagMap.get(Flag.PADDING);
    try {
      if (paddingFlag != null) {
        return RsaPadding.valueOf(paddingFlag.toUpperCase());
      }
    } catch (IllegalArgumentException e) {
      throw new KeyczarException(Messages.getString("InvalidPadding", paddingFlag));
    }
    return null;
  }

  @Override
  public int getKeySize() throws KeyczarException {
    if (flagMap.containsKey(Flag.SIZE)) {
      try {
        return Integer.parseInt(flagMap.get(Flag.SIZE));
      } catch (NumberFormatException e) {
        throw new KeyczarException("Error parsing key size", e);
      }
    } else {
      return -1;
    }
  }

  @Override
  public HmacKey getHmacKey() throws KeyczarException {
    return HmacKey.generate(DefaultKeyType.HMAC_SHA1.applyDefaultParameters(null));
  }
}
