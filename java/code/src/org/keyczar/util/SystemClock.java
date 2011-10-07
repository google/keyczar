package org.keyczar.util;

public class SystemClock implements Clock {
	@Override
	public long now() {
	  return System.currentTimeMillis();
	}
}
