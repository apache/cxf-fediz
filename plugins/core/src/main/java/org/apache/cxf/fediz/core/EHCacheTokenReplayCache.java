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

package org.apache.cxf.fediz.core;

import java.io.Closeable;
import java.io.IOException;
import java.net.URL;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Ehcache;
import net.sf.ehcache.Element;

import org.apache.ws.security.util.Loader;

/**
 * An in-memory EHCache implementation of the TokenReplayCache interface. 
 * The default TTL is 60 minutes.
 */
public class EHCacheTokenReplayCache implements TokenReplayCache<String>, Closeable {
    
    public static final long DEFAULT_TTL = 3600L;
    private static final String CACHE_KEY = "fediz-replay-cache";
    private Ehcache cache;
    private CacheManager cacheManager;
    private long ttl = DEFAULT_TTL;
    
    public EHCacheTokenReplayCache() {
        String defaultConfigFile = "fediz-ehcache.xml";
        URL configFileURL = Loader.getResource(defaultConfigFile);
        createCache(configFileURL);
    }
    
    public EHCacheTokenReplayCache(URL configFileURL) {
        createCache(configFileURL);
    }
    
    private void createCache(URL configFileURL) {
        if (configFileURL == null) {
            cacheManager = CacheManager.create();
        } else {
            cacheManager = CacheManager.create(configFileURL);
        }
        
        Ehcache newCache = new Cache(CACHE_KEY, 50000, true, false, DEFAULT_TTL, DEFAULT_TTL);
        cache = cacheManager.addCacheIfAbsent(newCache);
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
    
    /**
     * Add the given identifier to the cache. It will be cached for a default amount of time.
     * @param id The identifier to be added
     */
    @Override
    public void putId(String id) {
        if (id == null || "".equals(id)) {
            return;
        }
        
        int parsedTTL = (int)ttl;
        if (ttl != (long)parsedTTL) {
            // Fall back to 60 minutes if the default TTL is set incorrectly
            parsedTTL = 3600;
        }
        
        cache.put(new Element(id, id, false, parsedTTL, parsedTTL));
    }
    
    
    /**
     * Return the given identifier if it is contained in the cache, otherwise null.
     * @param id The identifier to check
     */
    public String getId(String id) {
        Element element = cache.get(id);
        if (element != null) {
            if (cache.isExpired(element)) {
                cache.remove(id);
                return null;
            }
            return (String)element.getObjectValue();
        }
        return null;
    }

    public void close() throws IOException {
        if (cacheManager != null) {
            cacheManager.shutdown();
            cacheManager = null;
            cache = null;
        }
    }
    
}
