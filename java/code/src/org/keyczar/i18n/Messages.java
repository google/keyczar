/*
 * Copyright 2008 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keyczar.i18n;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.keyczar.annotations.ForTesting;

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
