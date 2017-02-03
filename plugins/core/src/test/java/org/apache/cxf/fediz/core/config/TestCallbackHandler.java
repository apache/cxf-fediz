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
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.cxf.fediz.core.spi.HomeRealmCallback;
import org.apache.cxf.fediz.core.spi.IDPCallback;
import org.apache.cxf.fediz.core.spi.RealmCallback;
import org.apache.cxf.fediz.core.spi.ReplyCallback;
import org.apache.cxf.fediz.core.spi.SignInQueryCallback;
import org.apache.cxf.fediz.core.spi.WAuthCallback;
import org.apache.cxf.fediz.core.spi.WReqCallback;

public class TestCallbackHandler implements CallbackHandler {

    static final String TEST_HOME_REALM = "http://test.com/homerealm";
    static final String TEST_WTREALM = "http://test.com/wtrealm";
    static final String TEST_IDP = "http://rp.example.com/";
    static final String TEST_WAUTH = "up";
    static final String TEST_SIGNIN_QUERY = "pubid=myid";
    static final String TEST_REPLY = "http://apache.org/reply";
    static final String TEST_WREQ = 
        "<RequestSecurityToken xmlns=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\">"
        + "<TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1</TokenType>"
        + "</RequestSecurityToken>";
    
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof HomeRealmCallback) {
                HomeRealmCallback callback = (HomeRealmCallback) callbacks[i];
                callback.setHomeRealm(TEST_HOME_REALM);
            } else if (callbacks[i] instanceof RealmCallback) {
                RealmCallback callback = (RealmCallback)callbacks[i];
                callback.setRealm(TEST_WTREALM);
            } else if (callbacks[i] instanceof WAuthCallback) {
                WAuthCallback callback = (WAuthCallback) callbacks[i];
                callback.setWauth(TEST_WAUTH);
            } else if (callbacks[i] instanceof WReqCallback) {
                WReqCallback callback = (WReqCallback) callbacks[i];
                callback.setWreq(TEST_WREQ);
            } else if (callbacks[i] instanceof IDPCallback) {
                IDPCallback callback = (IDPCallback) callbacks[i];
                callback.setIssuerUrl(new URL(TEST_IDP));
            } else if (callbacks[i] instanceof SignInQueryCallback) {
                SignInQueryCallback callback = (SignInQueryCallback) callbacks[i];
                Map<String, String> queryParamMap = new HashMap<>();
                queryParamMap.put("pubid", "myid");
                queryParamMap.put("testenc", "<=>");
                callback.setSignInQueryParamMap(queryParamMap);
            } else if (callbacks[i] instanceof ReplyCallback) {
                ReplyCallback callback = (ReplyCallback) callbacks[i];
                callback.setReply(TEST_REPLY);
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }

}
