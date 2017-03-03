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
package org.apache.cxf.fediz.service.oidc;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.cxf.common.logging.LogUtils;
import org.apache.cxf.interceptor.security.NamePasswordCallbackHandler;

public class JAASAuthenticationStrategy implements ProviderAuthenticationStrategy {
    private static final Logger LOG = LogUtils.getL7dLogger(JAASAuthenticationStrategy.class);
    private String contextName;
    private Configuration loginConfig;

    @Override
    public boolean authenticate(String name, String password) {
        if (contextName != null) {
            try {
                // Login using JAAS
                CallbackHandler callbackHandler =
                    new NamePasswordCallbackHandler(name, password);
                LoginContext ctx = new LoginContext(contextName, null, callbackHandler, loginConfig);
                ctx.login();
                ctx.logout();
                return true;
            } catch (LoginException ex) {
                String errorMessage = "Authentication failed: " + ex.getMessage();
                LOG.log(Level.FINE, errorMessage, ex);
            }
        }
        return false;
    }

    public void setContextName(String contextName) {
        this.contextName = contextName;
    }

    public void setLoginConfig(Configuration loginConfig) {
        this.loginConfig = loginConfig;
    }

}
