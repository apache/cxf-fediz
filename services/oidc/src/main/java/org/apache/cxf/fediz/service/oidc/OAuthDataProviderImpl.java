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

import java.lang.reflect.Method;
import java.security.Principal;
import java.util.Collections;
import java.util.List;

import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.OAuthPermission;
import org.apache.cxf.rs.security.oauth2.grants.code.DefaultEHCacheCodeDataProvider;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.apache.cxf.rs.security.oidc.utils.OidcUtils;

public class OAuthDataProviderImpl extends DefaultEHCacheCodeDataProvider {

    private boolean checkOnlyRegisteredClients;
    private boolean persistUnregisteredClients = true;
    private ProviderAuthenticationStrategy authenticationStrategy;
    
    @Override
    public Client getClient(String clientId) {
        Client client = super.getClient(clientId);
        if (client != null || checkOnlyRegisteredClients) {
            return client;
        }

        String grantType = getCurrentRequestedGrantType();
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
                    return createClientCredClient(clientId, null);
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
            && !client.getAllowedGrantTypes().contains(OAuthConstants.RESOURCE_OWNER_GRANT)    
            && !requestedScopes.contains(OidcUtils.OPENID_SCOPE)) {
            throw new OAuthServiceException("Required scopes are missing");
        }
        return super.convertScopeToPermissions(client, requestedScopes);
    }

    public void setCheckOnlyRegisteredClients(boolean checkOnlyRegisteredClients) {
        this.checkOnlyRegisteredClients = checkOnlyRegisteredClients;
    }

    public void setPersistUnregisteredClients(boolean persistUnregisteredClients) {
        this.persistUnregisteredClients = persistUnregisteredClients;
    }

    public void setAuthenticationStrategy(ProviderAuthenticationStrategy authenticationStrategy) {
        this.authenticationStrategy = authenticationStrategy;
    }
    
    protected Client authenticateClient(String clientId, String clientSecret) {
        if (doAuthenticate(clientId, clientSecret)) {
            return createClientCredClient(clientId, clientSecret);
        }
        return null;
    }
    
    protected Client createClientCredClient(String clientId, String password) {
        Client c = new Client(clientId, password, true);
        c.setAllowedGrantTypes(Collections.singletonList(OAuthConstants.CLIENT_CREDENTIALS_GRANT));
        if (persistUnregisteredClients) {
            // It will enable seeing these clients and their tokens in the OIDC management console
            super.setClient(c);
        }
        return c;
    }

    protected boolean doAuthenticate(String id, String password) {
        return authenticationStrategy != null
            && authenticationStrategy.authenticate(id, password);
    }
    @Override
    public void setMessageContext(MessageContext mc) {
        super.setMessageContext(mc);
        if (authenticationStrategy != null) {
            try {
                Method contextMethod = authenticationStrategy.getClass().getMethod("setMessageContext",
                                                                              new Class[]{MessageContext.class});
                contextMethod.invoke(authenticationStrategy, new Object[]{mc});
            } catch (Throwable t) {
                // ignore
            }    
        }
    }
}
