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

package org.apache.cxf.fediz.core.config;

import java.io.IOException;
import java.net.URL;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.cxf.fediz.core.spi.HomeRealmCallback;
import org.apache.cxf.fediz.core.spi.IDPCallback;
import org.apache.cxf.fediz.core.spi.WAuthCallback;

public class TestCallbackHandler implements CallbackHandler {

    static final String TEST_HOME_REALM = "http://test.com/homerealm";
    static final String TEST_IDP = "http://rp.example.com/";
    static final String TEST_WAUTH = "up";
    
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof HomeRealmCallback) {
                HomeRealmCallback callback = (HomeRealmCallback) callbacks[i];
                callback.setHomeRealm(TEST_HOME_REALM);
            } else if (callbacks[i] instanceof WAuthCallback) {
                WAuthCallback callback = (WAuthCallback) callbacks[i];
                callback.setWauth(TEST_WAUTH);
            } else if (callbacks[i] instanceof IDPCallback) {
                IDPCallback callback = (IDPCallback) callbacks[i];
                callback.setIssuerUrl(new URL(TEST_IDP));
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }

}