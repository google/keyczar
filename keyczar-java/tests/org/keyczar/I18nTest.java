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

package org.keyczar;


import junit.framework.TestCase;

import org.junit.Test;
import org.keyczar.exceptions.BadVersionException;
import org.keyczar.exceptions.InvalidSignatureException;
import org.keyczar.exceptions.ShortBufferException;
import org.keyczar.i18n.Messages;

import java.lang.reflect.Method;
import java.util.Locale;

/**
 * Test internationalzied messages.
 *
 * @author steveweis@gmail.com (Steve Weis)
 */
public class I18nTest extends TestCase {
 
  @Test
  public final void testEnglish() throws Exception {
    String englishMessage = "Received a bad version number: 1";
    Messages.changeLocale(new Locale("en"));
    BadVersionException enEx = new BadVersionException((byte) 1);
    assertEquals(englishMessage, enEx.getMessage());
    
    String anotherEnglishMessage =
      "Input buffer is too short. Given: 20 bytes. Need: 10";
    ShortBufferException buffEx = new ShortBufferException(20, 10);
    assertEquals(anotherEnglishMessage, buffEx.getMessage());
  }
  
  @Test
  public final void testSpanish() throws Exception {
    String spanishMessage = "Recibido un mal número de versión: 1";
    Messages.changeLocale(new Locale("es"));
    BadVersionException esEx = new BadVersionException((byte) 1);
    assertEquals(spanishMessage, esEx.getMessage());
    
    String anotherSpanishMessage =
      "Buffer de entrada es mas corto. Recibido: 20 bytes. Necesarios: 10";
    ShortBufferException buffEx = new ShortBufferException(20, 10);
    assertEquals(anotherSpanishMessage, buffEx.getMessage());
  }
}
