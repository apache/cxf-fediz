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

package org.apache.cxf.fediz.service.oidc.logout;

import java.io.IOException;
import java.util.regex.Pattern;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.servlet.http.HttpServletRequest;

import org.apache.cxf.fediz.core.spi.ReplyConstraintCallback;
import org.apache.cxf.fediz.service.oidc.handler.hrd.ApplicationContextProvider;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.provider.OAuthDataProvider;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.springframework.context.ApplicationContext;

public class LogoutRedirectConstraintHandler implements CallbackHandler {
    
    private static final String CLIENT_LOGOUT_URI = "client_logout_uri";

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (callbacks != null) {
            for (Callback callback : callbacks) {
                if (callback instanceof ReplyConstraintCallback) {
                    ReplyConstraintCallback replyConstraintCallback = (ReplyConstraintCallback)callback;
                    HttpServletRequest request = replyConstraintCallback.getRequest();
                    if (request != null && request.getParameter(OAuthConstants.CLIENT_ID) != null) {
                        String clientId = request.getParameter(OAuthConstants.CLIENT_ID);

                        replyConstraintCallback.setReplyConstraint(getLogoutRedirectConstraint(clientId));
                    }
                }
            }
        }
    }

    private Pattern getLogoutRedirectConstraint(String clientId) {
        ApplicationContext ctx = ApplicationContextProvider.getApplicationContext();
        OAuthDataProvider dataManager = (OAuthDataProvider)ctx.getBean("oauthProvider");

        Client client = dataManager.getClient(clientId);
        if (client != null) {
            String logoutUri = client.getProperties().get(CLIENT_LOGOUT_URI);
            if (logoutUri != null) {
                return Pattern.compile(logoutUri);
            }
        }
        
        return null;
    }

}
