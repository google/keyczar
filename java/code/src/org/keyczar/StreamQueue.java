// Copyright 2012 Google Inc. All Rights Reserved.

package org.keyczar;

import org.keyczar.interfaces.Stream;

import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * A thread-safe queue for Streams and their derived classes.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 * @param <T>
 */
class StreamQueue<T extends Stream> extends ConcurrentLinkedQueue<T> {
	private static final long serialVersionUID = 4914617278167817144L;
}