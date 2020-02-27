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
package org.apache.cxf.fediz.service.oidc.handler.hrd;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.cxf.fediz.core.spi.HomeRealmCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This callback handler uses the login_hint parameter defined in OpenID Connect to discover the users home realm.
 *
 * It is expected that the login_hint will contain the users email address and that the domain name from the mail
 * address will be equal to the home realm identifier.
 */
public class LoginHintHomeRealmDiscovery implements CallbackHandler {

    private static final Logger LOG = LoggerFactory.getLogger(LoginHintHomeRealmDiscovery.class);

    public void handle(Callback[] callbacks) throws IOException,
        UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof HomeRealmCallback) {
                HomeRealmCallback callback = (HomeRealmCallback) callbacks[i];
                final String loginHint = (String)callback.getRequest().getParameter("login_hint");
                if (loginHint == null || loginHint.isEmpty()) {
                    LOG.debug("No login_hint found in request to set home realm");
                } else {
                    String[] homeRealm = loginHint.split("@");
                    if (homeRealm.length == 2) {
                        LOG.debug("Home realm '{}' found in request", homeRealm[1]);
                        callback.setHomeRealm(homeRealm[1]);
                    } else {
                        LOG.warn("login_hint is not an email address: {}", loginHint);
                    }
                }
            } else {
                LOG.warn("Callback is not an instance of HomeRealmCallback: {}", callbacks[i]);
            }
        }
    }

}
