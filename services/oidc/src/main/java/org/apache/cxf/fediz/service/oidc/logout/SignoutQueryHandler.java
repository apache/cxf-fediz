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
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.servlet.http.HttpServletRequest;

import org.apache.cxf.fediz.core.spi.SignOutQueryCallback;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;

/**
 * Set the client_id on the signout request to the IdP. This is needed after we redirect to the "finalize" method of 
 * the LogoutService.
 */
public class SignoutQueryHandler implements CallbackHandler {

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (callbacks != null) {
            for (Callback callback : callbacks) {
                if (callback instanceof SignOutQueryCallback) {
                    SignOutQueryCallback signOutQueryCallback = (SignOutQueryCallback)callback;
                    HttpServletRequest request = signOutQueryCallback.getRequest();
                    if (request != null && request.getParameter(OAuthConstants.CLIENT_ID) != null) {
                        Map<String, String> signOutQueryMap = new HashMap<>();
                        signOutQueryMap.put(OAuthConstants.CLIENT_ID, request.getParameter(OAuthConstants.CLIENT_ID));
                        signOutQueryCallback.setSignOutQueryParamMap(signOutQueryMap);
                    }
                }
            }
        }
    }


}
