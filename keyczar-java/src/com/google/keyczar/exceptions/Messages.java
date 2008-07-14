package com.google.keyczar.exceptions;

import com.google.keyczar.annotations.ForTesting;

import java.text.MessageFormat;
import java.util.Formatter;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

public class Messages {
  private static final String BUNDLE_NAME =
    "com.google.keyczar.exceptions.messages";

  private static ResourceBundle RESOURCE_BUNDLE =
    ResourceBundle.getBundle(BUNDLE_NAME);

  private Messages() {
  }
  
  @ForTesting
  public static void reloadBundle(Locale locale) {
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
