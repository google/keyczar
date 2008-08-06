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

import org.keyczar.interfaces.Stream;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Caches StreamQueue objects for KeyczarKeys so they can reused.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 * @param <T>
 */
class StreamCache<T extends Stream> {
  private final ConcurrentHashMap<KeyczarKey, StreamQueue<T>> cacheMap =
    new ConcurrentHashMap<KeyczarKey, StreamQueue<T>>();

  void put(KeyczarKey key, T s) {
    getQueue(key).add(s);
  }

  T get(KeyczarKey key) {
    return getQueue(key).poll();
  }

  StreamQueue<T> getQueue(KeyczarKey key) {
    StreamQueue<T> queue = cacheMap.get(key);
    if (queue != null) {
      return queue;
    }
    StreamQueue<T> freshQueue = new StreamQueue<T>();
    queue = cacheMap.putIfAbsent(key, freshQueue);
    if (queue != null) {
      // Another thread already inserted a fresh queue with this key.
      return queue;
    }
    return freshQueue;
  }
}

/**
 * A thread-safe queue for Streams and their derived classes.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 * @param <T>
 */
class StreamQueue<T extends Stream> extends ConcurrentLinkedQueue<T> {

}