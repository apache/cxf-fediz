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
import java.util.List;
import java.util.Map;

import org.apache.cxf.fediz.core.FedizPrincipal;
import org.apache.cxf.rs.security.oauth2.common.AccessTokenRegistration;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.OAuthPermission;
import org.apache.cxf.rs.security.oauth2.common.ServerAccessToken;
import org.apache.cxf.rs.security.oauth2.common.UserSubject;
import org.apache.cxf.rs.security.oauth2.grants.code.AuthorizationCodeRegistration;
import org.apache.cxf.rs.security.oauth2.grants.code.DefaultEHCacheCodeDataProvider;
import org.apache.cxf.rs.security.oauth2.grants.code.ServerAuthorizationCodeGrant;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.apache.cxf.rs.security.oidc.common.IdToken;
import org.apache.cxf.rs.security.oidc.idp.OidcUserSubject;
import org.apache.cxf.rs.security.oidc.utils.OidcUtils;

public class OAuthDataManager extends DefaultEHCacheCodeDataProvider {
    private SamlTokenConverter tokenConverter = new LocalSamlTokenConverter();
    
    public OAuthDataManager() {
    }
    
    @Override
    protected ServerAuthorizationCodeGrant doCreateCodeGrant(AuthorizationCodeRegistration reg) 
        throws OAuthServiceException {
        ServerAuthorizationCodeGrant grant = super.doCreateCodeGrant(reg);
        OidcUserSubject oidcSub = createOidcSubject(grant.getClient(), 
                                                    grant.getSubject(), 
                                                    reg.getNonce());
        grant.setSubject(oidcSub);
        return grant;
    }
    
    @Override
    protected ServerAccessToken doCreateAccessToken(AccessTokenRegistration reg)
        throws OAuthServiceException {
        ServerAccessToken token = super.doCreateAccessToken(reg);
        if (OAuthConstants.IMPLICIT_GRANT.equals(reg.getGrantType())) {
            OidcUserSubject oidcSub = createOidcSubject(token.getClient(), 
                                                        token.getSubject(), 
                                                        reg.getNonce());
            token.setSubject(oidcSub);
        }
        return token;
    }
    
    @Override
    public List<OAuthPermission> convertScopeToPermissions(Client client, List<String> requestedScopes) {
        if (!requestedScopes.contains(OidcUtils.OPENID_SCOPE)) {
            throw new OAuthServiceException("Required scope is missing");    
        }
        return super.convertScopeToPermissions(client, requestedScopes);
    }
    
    protected OidcUserSubject createOidcSubject(Client client, UserSubject subject, String nonce) {
        IdToken idToken = getIdToken(client, nonce);
        if (idToken != null) {
            OidcUserSubject oidcSub = new OidcUserSubject(subject);
            oidcSub.setIdToken(idToken);
            return oidcSub;
        }
        return null;
    }
    
    protected IdToken getIdToken(Client client, String nonce) {
        Principal principal = getMessageContext().getSecurityContext().getUserPrincipal();
        
        if (principal instanceof FedizPrincipal) {
            FedizPrincipal fedizPrincipal = (FedizPrincipal)principal; 
            return tokenConverter.convertToIdToken(fedizPrincipal.getLoginToken(),
                                                   fedizPrincipal.getName(), 
                                                   fedizPrincipal.getClaims(),
                                                   client.getClientId(),
                                                   nonce);
        } else {
            throw new OAuthServiceException("Unsupported Principal");
        }
    }

    public void setTokenConverter(SamlTokenConverter tokenConverter) {
        this.tokenConverter = tokenConverter;
    }

    @Override 
    public void init() {
        super.init();
        Map<String, OAuthPermission> perms = super.getPermissionMap();
        if (!perms.containsKey(OidcUtils.OPENID_SCOPE)) {
            perms.put(OidcUtils.OPENID_SCOPE,
                new OAuthPermission(OidcUtils.OPENID_SCOPE, "Access the authentication claims"));
        }
        perms.get(OidcUtils.OPENID_SCOPE).setDefault(true);
        
        if (!perms.containsKey(OAuthConstants.REFRESH_TOKEN_SCOPE)) {
            perms.put(OAuthConstants.REFRESH_TOKEN_SCOPE, 
                new OAuthPermission(OAuthConstants.REFRESH_TOKEN_SCOPE, "Refresh access tokens"));
        }
        perms.get(OAuthConstants.REFRESH_TOKEN_SCOPE).setInvisibleToClient(true);
        
    }
}
