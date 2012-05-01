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

package org.keyczar.interfaces;

import com.google.gson.InstanceCreator;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

import org.keyczar.DefaultKeyType;
import org.keyczar.KeyczarKey;

import org.keyczar.exceptions.KeyczarException;

import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The type of key, along with a list of acceptable (secure) key sizes.
 * 1
 *
 * @author jmscheiner@google.com (Justin Scheiner)
 */
public interface KeyType {

  /**
   * Returns the default (recommended) key size.
   *
   * @return default key size in bits
   */
  public int defaultSize();

  /**
   * @return the output size for the default key size
   */
  public int getOutputSize();

  /**
   * @param keySize the key size to get the output size for
   * @return the output size for the given key size
   */
  public int getOutputSize(int keySize);

  /**
   * Checks whether a given key size is acceptable.
   *
   * @param size integer key size
   * @return True if size is acceptable, False otherwise.
   */
  public boolean isAcceptableSize(int size);

  /**
   * @return a list of acceptable sizes for this key type
   */
  public List<Integer> getAcceptableSizes();

  /**
   * The value representing the key type when serialized.
   *
   * @return the integer value representing
   */
  public int getValue();

  /**
   * Creates {@link KeyczarKey}s from their serialized form or from scratch.
   *
   * TODO(jmscheiner): This bit of misdirection isn't necessary, but makes
   * backwards compatibility with the existing keys more straightforward.
   */
  public interface Builder {
    /**
     * Reads a {@link KeyczarKey} from its serialized form.
     *
     * @return the deserialized key
     * @throws KeyczarException if there is an issue deserializing the key
     */
    public KeyczarKey read(String s) throws KeyczarException;

    /**
     * Generates a key of this type, of the given size.
     *
     * @param keySize a valid key size, from {@link #getAcceptableSizes}.
     * @return a new {@link KeyczarKey}
     * @throws KeyczarException for key creation creation errors
     */
    public KeyczarKey generate(int keySize) throws KeyczarException;
  }

  /**
   * @return a reader for this key type
   */
  public Builder getBuilder();

  /**
   * Serializer based on the key type's value.
   */
  public static class KeyTypeSerializer implements JsonSerializer<KeyType> {
    @Override
    public JsonElement serialize(KeyType src,
        Type type, JsonSerializationContext context) {
      return new JsonPrimitive(src.getValue());
    }
  }

  /**
   * Trivial deserialization based on the key value.
   *
   * TODO(jmscheiner): This could alternately be written as a switch that
   * forwards deserialization to the default for the actual class.
   */
  public static class KeyTypeDeserializer implements JsonDeserializer<KeyType> {
    private static Map<String, Class<? extends KeyType>> typeMap
        = new HashMap<String, Class<? extends KeyType>>();

    static {
      for (DefaultKeyType key : DefaultKeyType.values()) {
        // Register default key types.
        registerType(key.name(), key.getClass());
      }
      System.out.println(typeMap);
    }

    public static void registerType(String name,
        Class<? extends KeyType> keyType) {
      if (typeMap.containsKey(name)) {
        throw new IllegalArgumentException(
            "Attempt to map two key types to the same name " + name);
      }
      typeMap.put(name, keyType);
    }

    @Override
    public KeyType deserialize(JsonElement json, Type type,
        JsonDeserializationContext context) throws JsonParseException {
      String keyName = json.getAsJsonPrimitive().getAsString();
      if (!typeMap.containsKey(keyName)) {
        throw new IllegalArgumentException("Cannot deserialize "
            + keyName + " no such key has been registered.");
      }

      try {
        // Since the default key types do not have a default constructor,
        // create them explicitly.
        KeyType defaultKey = DefaultKeyType.getTypeByName(keyName);
        if (defaultKey != null) {
          return defaultKey;
        } else {
          System.out.println(
              "Found " + keyName + " is not a key in the mapping.");
        }

        // Otherwise create the key from its required default constructor.
        return typeMap.get(keyName).newInstance();
      } catch (InstantiationException e) {
        throw new JsonParseException(e);
      } catch (IllegalAccessException e) {
        throw new JsonParseException(e);
      }
    }
  }

  /**
   * The {@link InstanceCreator} is a stub, creation happens as part of
   * deserialization.
   */
  public static class KeyTypeInstanceCreator
      implements InstanceCreator<KeyType> {
    @Override
    public KeyType createInstance(Type type) {
      return null;
    }
  }
}
