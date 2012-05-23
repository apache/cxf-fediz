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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

//[TODO] add properties TokenReplayCacheExpirationPeriod
public final class TokenReplayCacheInMemory<T> implements TokenReplayCache<T> {

    /**
     * 
     */
    private static final long serialVersionUID = 7269477566842444549L;

    private static TokenReplayCache<String> instance;
    
    private List<T> cache;
    
    private TokenReplayCacheInMemory() {
        cache = Collections.synchronizedList(new ArrayList<T>());
    }

    public static synchronized TokenReplayCache<String> getInstance() {
        if (instance != null) {
            return instance;
        }
        instance = new TokenReplayCacheInMemory<String>();
        return instance;
    }

    @Override
    public T getId(T id) {
        int index = cache.indexOf(id);
        if (index == -1) {
            return null;
        } else {
            return cache.get(index);
        }
    }

    @Override
    public void putId(T id) {
        cache.add(id);
    }


}
