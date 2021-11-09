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

import org.apache.cxf.fediz.core.RequestState;
import org.apache.wss4j.common.util.Loader;
import org.ehcache.Cache;
import org.ehcache.CacheManager;
import org.ehcache.config.builders.CacheManagerBuilder;
import org.ehcache.xml.XmlConfiguration;

/**
 * An in-memory EHCache implementation of the SPStateManager interface.
 * The default TTL is 5 minutes.
 */
public class EHCacheSPStateManager implements SPStateManager {

    public static final String REQUEST_CACHE_KEY = "cxf.fediz.samlp.request.state.cache";
    public static final String RESPONSE_CACHE_KEY = "cxf.fediz.samlp.response.state.cache";

    private Cache<String, RequestState> requestCache;
    private Cache<String, ResponseState> responseCache;
    private CacheManager cacheManager;

    public EHCacheSPStateManager(String configFile) {
        this(getConfigFileURL(configFile));
    }

    public EHCacheSPStateManager(URL configFileURL) {
        XmlConfiguration xmlConfig = new XmlConfiguration(configFileURL);
        cacheManager = CacheManagerBuilder.newCacheManager(xmlConfig); 
        cacheManager.init();
        initCache();
    }

    public EHCacheSPStateManager(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
        initCache();
    }

    private static URL getConfigFileURL(String configFile) {
        try {
            URL url = Loader.getResource(configFile);
            if (url == null) {
                url = new URL(configFile);
            }
            return url;
        } catch (IOException e) {
            // Do nothing
        }
        return null;
    }

    private void initCache() {
        requestCache = cacheManager.getCache(REQUEST_CACHE_KEY, String.class, RequestState.class);
        responseCache = cacheManager.getCache(RESPONSE_CACHE_KEY, String.class, ResponseState.class);
    }

    public void setRequestState(String relayState, RequestState state) {
        if (relayState != null && !relayState.isEmpty()) {
            requestCache.put(relayState, state);
        }
    }

    public RequestState removeRequestState(String relayState) {
        RequestState state = requestCache.get(relayState);
        if (state != null) {
            requestCache.remove(relayState);
        }
        return state;
    }

    public ResponseState getResponseState(String securityContextKey) {
        return responseCache.get(securityContextKey);
    }

    public void setResponseState(String securityContextKey, ResponseState state) {
        if (securityContextKey != null && !securityContextKey.isEmpty()) {
            responseCache.put(securityContextKey, state);
        }
    }

    public ResponseState removeResponseState(String securityContextKey) {
        ResponseState state = responseCache.get(securityContextKey);
        if (state != null) {
            responseCache.remove(securityContextKey);
        }
        return state;
    }

    public void close() throws IOException {
        if (cacheManager != null) {
            cacheManager.close();
            cacheManager = null;
            requestCache = null;
            responseCache = null;
        }
    }

}
