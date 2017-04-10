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
import javax.servlet.http.HttpServletRequest;

import org.apache.cxf.fediz.core.spi.HomeRealmCallback;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.provider.OAuthDataProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;

public class ClientIdHomeRealmDiscovery implements CallbackHandler {

    private static final Logger LOG = LoggerFactory.getLogger(ClientIdHomeRealmDiscovery.class);

    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof HomeRealmCallback) {
                HomeRealmCallback callback = (HomeRealmCallback) callbacks[i];

                HttpServletRequest request = callback.getRequest();
                String clientId = request.getParameter("client_id");

                if (clientId != null) {
                    ApplicationContext ctx = ApplicationContextProvider.getApplicationContext();
                    OAuthDataProvider dataManager = (OAuthDataProvider)ctx.getBean("oauthProvider");

                    Client client = dataManager.getClient(clientId);
                    if (client != null) {
                        callback.setHomeRealm(client.getHomeRealm());
                        LOG.debug("Retrieved home realm {}", callback.getHomeRealm());
                    }

                }

            } else {
                LOG.warn("Callback is not an instance of HomeRealmCallback: {}", callbacks[i]);
            }
        }
    }

}