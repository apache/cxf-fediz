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
package org.apache.cxf.fediz.service.idp;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class AuthContext implements Map<String, Object> {

    public static final String CURRENT_STATE = "current-state";
    public static final String INVALIDATE_SESSION = "invalidate-session";
    public static final String IDP_PRINCIPAL = "IDP_PRINCIPAL";
    public static final String AUTH_USERNAME = "auth-username";
    public static final String AUTH_PASSWORD = "auth-password";


    private HttpSession session;
    private HttpServletRequest request;

    public AuthContext(HttpSession session, HttpServletRequest request) {
        this.session = session;
        this.request = request;
    }

    @Override
    public int size() {
        throw new UnsupportedOperationException("method 'size' not supported");
    }

    @Override
    public boolean isEmpty() {
        throw new UnsupportedOperationException("method 'isEmpty' not supported");
    }

    @Override
    public boolean containsKey(Object key) {
        throw new UnsupportedOperationException("method 'containsKey' not supported");
    }

    @Override
    public boolean containsValue(Object value) {
        throw new UnsupportedOperationException("method 'containsValue' not supported");
    }

    @Override
    public Object get(Object key) {
        Object value = request.getAttribute((String)key);
        if (value != null) {
            return value;
        }
        value = session.getAttribute((String)key);
        return value;
    }

    @Override
    public Object put(String key, Object value) {
        Object oldValue = request.getAttribute((String)key);
        request.setAttribute(key, value);
        return oldValue;
    }
    
    public Object put(String key, Object value, boolean storeInSession) {
        Object oldValue = null;
        if (storeInSession) {
            oldValue = session.getAttribute((String)key);
            session.setAttribute(key, value);
        } else {
            oldValue = request.getAttribute((String)key);
            request.setAttribute(key, value);
        }
        return oldValue;
    }

    @Override
    public Object remove(Object key) {
        Object value = request.getAttribute((String)key);
        if (value != null) {
            request.removeAttribute((String)key);
        }
        value = session.getAttribute((String)key);
        if (value != null) {
            session.removeAttribute((String)key);
        }
        return value;
    }

    @Override
    public void putAll(Map<? extends String, ? extends Object> m) {
        throw new UnsupportedOperationException("method 'putAll' not supported");
    }

    @Override
    public void clear() {
        throw new UnsupportedOperationException("method 'clear' not supported");
    }

    @Override
    public Set<String> keySet() {
        throw new UnsupportedOperationException("method 'keySet' not supported");
    }

    @Override
    public Collection<Object> values() {
        throw new UnsupportedOperationException("method 'values' not supported");
    }

    @Override
    public Set<java.util.Map.Entry<String, Object>> entrySet() {
        throw new UnsupportedOperationException("method 'entrySet' not supported");
    }

}
