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

import java.security.Principal;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.cxf.common.logging.LogUtils;
import org.apache.cxf.interceptor.security.NamePasswordCallbackHandler;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.OAuthPermission;
import org.apache.cxf.rs.security.oauth2.grants.code.DefaultEHCacheCodeDataProvider;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.apache.cxf.rs.security.oidc.utils.OidcUtils;

public class OAuthDataProviderImpl extends DefaultEHCacheCodeDataProvider {
    
    private static final Logger LOG = LogUtils.getL7dLogger(OAuthDataProviderImpl.class);
    
    private boolean checkOnlyRegisteredClients;
    private String contextName;
    private Configuration loginConfig;

    
    @Override
    public Client getClient(String clientId) {
        //TODO: push most of this code into the abstract class
        Client client = super.getClient(clientId);
        if (client != null || checkOnlyRegisteredClients) {
            return client;
        }
        
        String grantType = (String)getMessageContext().get(OAuthConstants.GRANT_TYPE);
        if (OAuthConstants.CLIENT_CREDENTIALS_GRANT.equals(grantType)) {
            // Pre-registering the OAuth2 Client representations for 
            // "client_credentials" can be difficult. 
            
            String clientSecret = (String)getMessageContext().get(OAuthConstants.CLIENT_SECRET);
            if (clientSecret != null) {
                // Direct authentication with the back-end storage
                return authenticateClient(clientId, clientSecret);
            } else {
                Principal p = super.getMessageContext().getSecurityContext().getUserPrincipal();
                if (clientId.equals(p.getName())) {
                    Client c = new Client(clientId, null, true);
                    c.setAllowedGrantTypes(Collections.singletonList(OAuthConstants.CLIENT_CREDENTIALS_GRANT));
                    return c;
                }
            }
        }
        return null;
    }

    @Override
    public List<OAuthPermission> convertScopeToPermissions(Client client, List<String> requestedScopes) {
        //TODO: push this code into the abstract class
        //NOTE: if OIDC-registered clients will be allowed to support not only code/implicit
        // (as it is now) but also client credentials/etc then the check below will need to be more strict
        // with the help of getMessageContext().get(OAuthConstants.GRANT_TYPE)
        if (!client.getAllowedGrantTypes().contains(OAuthConstants.CLIENT_CREDENTIALS_GRANT)
            && !requestedScopes.contains(OidcUtils.OPENID_SCOPE)) {
            throw new OAuthServiceException("Required scopes are missing"); 
        }
        return super.convertScopeToPermissions(client, requestedScopes);
    }
    
    protected Client authenticateClient(String clientId, String clientSecret) {
        if (contextName != null) {
            try {
                // Login using JAAS
                CallbackHandler callbackHandler = 
                    new NamePasswordCallbackHandler(clientId, clientSecret);
                LoginContext ctx = new LoginContext(getContextName(), null, callbackHandler, loginConfig);  
                ctx.login();
                Client client = new Client(clientId, clientSecret, true);
                client.setAllowedGrantTypes(Collections.singletonList(OAuthConstants.CLIENT_CREDENTIALS_GRANT));
                ctx.logout();
                return client;
            } catch (LoginException ex) {
                String errorMessage = "Authentication failed: " + ex.getMessage();
                LOG.log(Level.FINE, errorMessage, ex);
            }
        }
        return null;
    }

    public void setCheckOnlyRegisteredClients(boolean checkOnlyRegisteredClients) {
        this.checkOnlyRegisteredClients = checkOnlyRegisteredClients;
    }
    
    public String getContextName() {
        return contextName;
    }

    public void setContextName(String contextName) {
        this.contextName = contextName;
    }

    public Configuration getLoginConfig() {
        return loginConfig;
    }

    public void setLoginConfig(Configuration loginConfig) {
        this.loginConfig = loginConfig;
    }

}
