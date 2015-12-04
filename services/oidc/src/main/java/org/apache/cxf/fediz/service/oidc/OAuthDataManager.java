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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.cxf.fediz.core.FedizPrincipal;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactProducer;
import org.apache.cxf.rs.security.jose.jws.JwsSignatureProvider;
import org.apache.cxf.rs.security.jose.jws.JwsUtils;
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
import org.apache.cxf.rs.security.oauth2.utils.OAuthUtils;
import org.apache.cxf.rs.security.oidc.common.IdToken;
import org.apache.cxf.rs.security.oidc.utils.OidcUtils;

public class OAuthDataManager extends DefaultEHCacheCodeDataProvider {

    private static final OAuthPermission OPENID_PERMISSION;
    private static final OAuthPermission REFRESH_TOKEN_PERMISSION;
    
    static {
        OPENID_PERMISSION = new OAuthPermission(OidcUtils.OPENID_SCOPE, 
            "Access the authentication claims");
        OPENID_PERMISSION.setDefault(true);
        REFRESH_TOKEN_PERMISSION = new OAuthPermission(OAuthConstants.REFRESH_TOKEN_SCOPE, 
            "Refresh access tokens");
        REFRESH_TOKEN_PERMISSION.setInvisibleToClient(true);
    }

    private Map<String, OAuthPermission> permissionMap = new HashMap<String, OAuthPermission>();
    private MessageContext messageContext;
    private SamlTokenConverter tokenConverter = new LocalSamlTokenConverter();
    private boolean signIdTokenWithClientSecret;
    
    
    public OAuthDataManager() {
        permissionMap.put(OPENID_PERMISSION.getPermission(), OPENID_PERMISSION);
        permissionMap.put(REFRESH_TOKEN_PERMISSION.getPermission(), REFRESH_TOKEN_PERMISSION);
    }
    
    public OAuthDataManager(Map<String, OAuthPermission> permissionMap) {
        this.permissionMap = permissionMap;
    }
    
    @Override
    protected ServerAuthorizationCodeGrant doCreateCodeGrant(AuthorizationCodeRegistration reg) 
        throws OAuthServiceException {
        ServerAuthorizationCodeGrant grant = super.doCreateCodeGrant(reg);
        createIdToken(grant.getClient(), grant.getSubject(), reg.getNonce());
        return grant;
    }
    
    @Override
    protected ServerAccessToken doCreateAccessToken(AccessTokenRegistration reg)
        throws OAuthServiceException {
        ServerAccessToken token = super.doCreateAccessToken(reg);
        createIdToken(token.getClient(), token.getSubject(), reg.getNonce());
        return token;
    }
    
    // Scope to Permission conversion
    @Override
    public List<OAuthPermission> convertScopeToPermissions(Client client, List<String> scopes)
            throws OAuthServiceException {
        List<OAuthPermission> list = new ArrayList<OAuthPermission>();
        for (String scope : scopes) {
            OAuthPermission permission = permissionMap.get(scope);
            if (permission == null) {
                throw new OAuthServiceException("Unexpected scope: " + scope);
            }
            list.add(permission);
        }
        if (!list.contains(OPENID_PERMISSION)) {
            throw new OAuthServiceException("Default scope is missing");
        }
        return list;
    }

    public void setMessageContext(MessageContext messageContext) {
        this.messageContext = messageContext;
    }

    public void setScopes(Map<String, String> scopes) {
        for (Map.Entry<String, String> entry : scopes.entrySet()) {
            OAuthPermission permission = new OAuthPermission(entry.getKey(), entry.getValue());
            if (OidcUtils.OPENID_SCOPE.equals(entry.getKey())) {
                permission.setDefault(true);
            } else if (OAuthConstants.REFRESH_TOKEN_SCOPE.equals(entry.getKey())) {
                permission.setInvisibleToClient(true);
            } 
            permissionMap.put(entry.getKey(), permission);
        }
    }

    protected void createIdToken(Client client, UserSubject subject, String nonce) {
        if (subject != null && !subject.getProperties().containsKey(OidcUtils.ID_TOKEN)) {
            Principal principal = messageContext.getSecurityContext().getUserPrincipal();
            
            if (principal instanceof FedizPrincipal) {
                String joseIdToken = getJoseIdToken((FedizPrincipal)principal, client, nonce);
                subject.getProperties().put(OidcUtils.ID_TOKEN, joseIdToken);
            }
        }
        
    }
    
    protected String getJoseIdToken(FedizPrincipal principal, Client client, String nonce) {
        IdToken idToken = tokenConverter.convertToIdToken(principal.getLoginToken(),
                                                          principal.getName(), 
                                                          principal.getClaims(),
                                                          client.getClientId(),
                                                          nonce);
        JwsJwtCompactProducer p = new JwsJwtCompactProducer(idToken);
        return p.signWith(getJwsSignatureProvider(client));
        // the JWS compact output may also need to be encrypted
    }

    protected JwsSignatureProvider getJwsSignatureProvider(Client client) {
        if (signIdTokenWithClientSecret && client.isConfidential()) {
            return OAuthUtils.getClientSecretSignatureProvider(client.getClientSecret());
        } 
        return JwsUtils.loadSignatureProvider(true);
        
    }
    
    /**
     * Enable the symmetric signature with the client secret. 
     * This property will be ignored if a client is public 
     */
    public void setSignIdTokenWithClientSecret(boolean signIdTokenWithClientSecret) {
        this.signIdTokenWithClientSecret = signIdTokenWithClientSecret;
    }

    public boolean isSignIdTokenWithClientSecret() {
        return signIdTokenWithClientSecret;
    }
    
    public void setTokenConverter(SamlTokenConverter tokenConverter) {
        this.tokenConverter = tokenConverter;
    }

    
}
