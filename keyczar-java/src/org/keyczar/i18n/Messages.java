package org.keyczar.i18n;

import org.keyczar.annotations.ForTesting;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * TODO(steveweis): javadoc this
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class Messages {
  private static final String BUNDLE_NAME = "org.keyczar.i18n.messages";

  private static ResourceBundle RESOURCE_BUNDLE = ResourceBundle
      .getBundle(BUNDLE_NAME);

  private Messages() {
  }

  @ForTesting
  public static void changeLocale(Locale locale) {
    RESOURCE_BUNDLE = ResourceBundle.getBundle(BUNDLE_NAME, locale);
  }

  public static String getString(String key, Object... params) {
    try {
      return MessageFormat.format(RESOURCE_BUNDLE.getString(key), params);
    } catch (MissingResourceException e) {
      return '!' + key + '!';
    }
  }
}