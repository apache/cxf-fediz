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

import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.grants.code.DefaultEHCacheCodeDataProvider;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;

public class OAuthDataProviderImpl extends DefaultEHCacheCodeDataProvider {
    
    private boolean checkOnlyRegisteredClients;
    
    @Override
    public Client getClient(String clientId) {
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
                    // Client was already authenticated with Servlet Security 
                    // or CXF (JAAS/etc) filters
                    return new Client(clientId, null, true);
                }
            }
        }
        return null;
    }

    protected Client authenticateClient(String clientId, String clientSecret) {
        // If the authentication is successful: 
        // return new Client(clientId, clientSecret, true)
        return null;
    }

    public void setCheckOnlyRegisteredClients(boolean checkOnlyRegisteredClients) {
        this.checkOnlyRegisteredClients = checkOnlyRegisteredClients;
    }

}
