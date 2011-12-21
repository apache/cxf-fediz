package org.apache.cxf.fediz.core;

public interface TokenReplayCache<T> {

	public abstract T getId(String id);

	public abstract void putId(T id);

}