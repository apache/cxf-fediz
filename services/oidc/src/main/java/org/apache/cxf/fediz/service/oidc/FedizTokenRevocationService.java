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

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.SecurityContext;

import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.services.TokenRevocationService;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.apache.cxf.rs.security.oauth2.utils.OAuthUtils;
import org.apache.cxf.security.transport.TLSSessionInfo;

/**
 * Override the default CXF class to pick up the fix that was made in 3.2.11/3.3.4 in the AbstractTokenService
 */
public class FedizTokenRevocationService extends TokenRevocationService {

    @Override
    protected Client authenticateClientIfNeeded(MultivaluedMap<String, String> params) {
        Client client = null;
        SecurityContext sc = getMessageContext().getSecurityContext();
        Principal principal = sc.getUserPrincipal();

        String clientId = retrieveClientId(params);
        if (principal == null) {
            if (clientId != null) {
                String clientSecret = params.getFirst(OAuthConstants.CLIENT_SECRET);
                if (clientSecret != null) {
                    client = getAndValidateClientFromIdAndSecret(clientId, clientSecret, params);
                    validateClientAuthenticationMethod(client, OAuthConstants.TOKEN_ENDPOINT_AUTH_POST);
                } else if (OAuthUtils.isMutualTls(sc, getTlsSessionInfo())) {
                    client = getClient(clientId, params);
                    checkCertificateBinding(client, getTlsSessionInfo());
                    validateClientAuthenticationMethod(client, OAuthConstants.TOKEN_ENDPOINT_AUTH_TLS);
                } else if (isCanSupportPublicClients()) {
                    client = getValidClient(clientId, params);
                    if (!isValidPublicClient(client, clientId)) {
                        client = null;
                    } else {
                        validateClientAuthenticationMethod(client, OAuthConstants.TOKEN_ENDPOINT_AUTH_NONE);
                    }
                }
            }
        } else {
            if (clientId != null) {
                if (!clientId.equals(principal.getName())) {
                    reportInvalidClient();
                }

                client = (Client)getMessageContext().get(Client.class.getName());
                if (client == null) {
                    client = getClient(clientId, params);
                }
            } else if (principal.getName() != null) {
                client = getClient(principal.getName(), params);
            } 
        }
        if (client == null) {
            client = getClientFromTLSCertificates(sc, getTlsSessionInfo(), params);
            if (client == null) {
                // Basic Authentication is expected by default
                client = getClientFromBasicAuthScheme(params);
            }
        }
        if (client == null) {
            reportInvalidClient();
        }
        return client;
    }
    
    private TLSSessionInfo getTlsSessionInfo() {

        return (TLSSessionInfo)getMessageContext().get(TLSSessionInfo.class.getName());
    }

}
