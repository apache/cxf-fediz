/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.cxf.fediz.cxf.plugin.state;

import java.io.IOException;
import java.net.URL;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Ehcache;
import net.sf.ehcache.Element;
import net.sf.ehcache.config.CacheConfiguration;
import org.apache.cxf.fediz.core.RequestState;
import org.apache.wss4j.common.cache.EHCacheManagerHolder;
import org.apache.wss4j.common.util.Loader;

/**
 * An in-memory EHCache implementation of the SPStateManager interface.
 * The default TTL is 5 minutes.
 */
public class EHCacheSPStateManager implements SPStateManager {

    public static final long DEFAULT_TTL = 60L * 5L;
    public static final String REQUEST_CACHE_KEY = "cxf.fediz.samlp.request.state.cache";
    public static final String RESPONSE_CACHE_KEY = "cxf.fediz.samlp.response.state.cache";

    private Ehcache requestCache;
    private Ehcache responseCache;
    private CacheManager cacheManager;
    private long ttl = DEFAULT_TTL;

    public EHCacheSPStateManager(String configFile) {
        this(getConfigFileURL(configFile));
    }

    public EHCacheSPStateManager(URL configFileURL) {
        this(EHCacheManagerHolder.getCacheManager("", configFileURL));
    }

    public EHCacheSPStateManager(CacheManager cacheManager) {
        this.cacheManager = cacheManager;

        CacheConfiguration requestCC = EHCacheManagerHolder.getCacheConfiguration(REQUEST_CACHE_KEY, cacheManager);

        Ehcache newCache = new Cache(requestCC);
        requestCache = cacheManager.addCacheIfAbsent(newCache);

        CacheConfiguration responseCC = EHCacheManagerHolder.getCacheConfiguration(RESPONSE_CACHE_KEY, cacheManager);

        newCache = new Cache(responseCC);
        responseCache = cacheManager.addCacheIfAbsent(newCache);
    }

    private static URL getConfigFileURL(Object o) {
        if (o instanceof String) {
            try {
                URL url = Loader.getResource((String)o);
                if (url == null) {
                    url = new URL((String)o);
                }
                return url;
            } catch (IOException e) {
                // Do nothing
            }
        } else if (o instanceof URL) {
            return (URL)o;
        }
        return null;
    }

    /**
     * Set a new (default) TTL value in seconds
     * @param newTtl a new (default) TTL value in seconds
     */
    public void setTTL(long newTtl) {
        ttl = newTtl;
    }

    /**
     * Get the (default) TTL value in seconds
     * @return the (default) TTL value in seconds
     */
    public long getTTL() {
        return ttl;
    }

    public void setRequestState(String relayState, RequestState state) {
        if (relayState == null || "".equals(relayState)) {
            return;
        }

        int parsedTTL = (int)ttl;
        if (ttl != (long)parsedTTL) {
            // Fall back to 60 minutes if the default TTL is set incorrectly
            parsedTTL = 3600;
        }

        Element element = new Element(relayState, state);
        element.setTimeToLive(parsedTTL);
        element.setTimeToIdle(parsedTTL);
        requestCache.put(element);
    }

    public RequestState removeRequestState(String relayState) {
        Element element = requestCache.get(relayState);
        if (element != null) {
            requestCache.remove(relayState);
            return (RequestState)element.getObjectValue();
        }
        return null;
    }

    public ResponseState getResponseState(String securityContextKey) {
        Element element = responseCache.get(securityContextKey);
        if (element != null) {
            if (responseCache.isExpired(element)) {
                responseCache.remove(securityContextKey);
                return null;
            }
            return (ResponseState)element.getObjectValue();
        }
        return null;
    }

    public ResponseState removeResponseState(String securityContextKey) {
        Element element = responseCache.get(securityContextKey);
        if (element != null) {
            responseCache.remove(securityContextKey);
            return (ResponseState)element.getObjectValue();
        }
        return null;
    }

    public void setResponseState(String securityContextKey, ResponseState state) {
        if (securityContextKey == null || "".equals(securityContextKey)) {
            return;
        }

        int parsedTTL = (int)ttl;
        if (ttl != (long)parsedTTL) {
            // Fall back to 5 minutes if the default TTL is set incorrectly
            parsedTTL = 60 * 5;
        }
        Element element = new Element(securityContextKey, state);
        element.setTimeToLive(parsedTTL);
        element.setTimeToIdle(parsedTTL);

        responseCache.put(element);
    }

    public void close() throws IOException {
        if (cacheManager != null) {
            cacheManager.shutdown();
            cacheManager = null;
            requestCache = null;
            responseCache = null;
        }
    }

}
