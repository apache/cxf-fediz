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
import java.util.concurrent.ConcurrentHashMap;

import org.apache.cxf.fediz.core.FedizPrincipal;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactProducer;
import org.apache.cxf.rs.security.jose.jws.NoneJwsSignatureProvider;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.OAuthPermission;
import org.apache.cxf.rs.security.oauth2.common.ServerAccessToken;
import org.apache.cxf.rs.security.oauth2.grants.code.AbstractCodeDataProvider;
import org.apache.cxf.rs.security.oauth2.grants.code.ServerAuthorizationCodeGrant;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.tokens.refresh.RefreshToken;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.apache.cxf.rs.security.oidc.common.IdToken;
import org.apache.cxf.rs.security.oidc.utils.OidcUtils;

public class OAuthDataManager extends AbstractCodeDataProvider {

    private static final OAuthPermission OPENID_PERMISSION;
    
    static {
        OPENID_PERMISSION = new OAuthPermission(OidcUtils.OPENID_SCOPE, "Access the claims about the authentication");
        OPENID_PERMISSION.setDefault(true);
    }

    private Map<String, OAuthPermission> permissionMap = new HashMap<String, OAuthPermission>();
    private MessageContext messageContext;
    private SamlTokenConverter tokenConverter = new LocalSamlTokenConverter();
    private Map<String, Client> clients = new ConcurrentHashMap<String, Client>();
    private Map<String, ServerAccessToken> accessTokens = new ConcurrentHashMap<String, ServerAccessToken>();
    private Map<String, RefreshToken> refreshTokens = new ConcurrentHashMap<String, RefreshToken>();
    private Map<String, ServerAuthorizationCodeGrant> codeGrants = 
            new ConcurrentHashMap<String, ServerAuthorizationCodeGrant>();
    
    
    
    public OAuthDataManager() {
        permissionMap.put(OPENID_PERMISSION.getPermission(), OPENID_PERMISSION);
    }
    
    public OAuthDataManager(Map<String, OAuthPermission> permissionMap) {
        this.permissionMap = permissionMap;
    }
    
    public void registerClient(Client c) {
        clients.put(c.getClientId(), c);
    }

    public Client getClient(String clientId) throws OAuthServiceException {
        return clients.get(clientId);
    }

    // Grants
    @Override
    protected void saveCodeGrant(ServerAuthorizationCodeGrant grant) {
        Principal principal = messageContext.getSecurityContext().getUserPrincipal();
        
        if (principal instanceof FedizPrincipal) {
            grant.getSubject().getProperties().put("id_token", 
                    getJoseIdToken((FedizPrincipal)principal,
                                grant.getClient().getClientId()));
        } else {
            throw new OAuthServiceException("Unsupported principal");
        }
        doSaveCodeGrant(grant);
    }

    protected void doSaveCodeGrant(ServerAuthorizationCodeGrant grant) {
        codeGrants.put(grant.getCode(), grant);
        
    }

    protected String getJoseIdToken(FedizPrincipal principal, String clientId) {
        IdToken jwtClaims = tokenConverter.convertToIdToken(principal.getLoginToken().getOwnerDocument(),
                                                          principal.getName(), 
                                                          clientId);
        JwsJwtCompactProducer p = new JwsJwtCompactProducer(jwtClaims);
        return p.signWith(new NoneJwsSignatureProvider());
    }

    @Override
    public ServerAuthorizationCodeGrant removeCodeGrant(String code) throws OAuthServiceException {
        return codeGrants.remove(code);
    }

    // Access Tokens
    @Override
    protected void saveAccessToken(ServerAccessToken token) {
        accessTokens.put(token.getTokenKey(), token);
    }

    @Override
    protected boolean revokeAccessToken(String tokenKey) {
        return accessTokens.remove(tokenKey) != null;
    }

    @Override
    public ServerAccessToken getAccessToken(String tokenId) throws OAuthServiceException {
        return accessTokens.get(tokenId);
    }

    // Refresh Tokens
    @Override
    protected void saveRefreshToken(ServerAccessToken accessToken, RefreshToken refreshToken) {
        refreshTokens.put(refreshToken.getTokenKey(), refreshToken);
    }

    @Override
    protected RefreshToken revokeRefreshToken(Client c, String tokenKey) {
        return refreshTokens.remove(tokenKey);
    }

    @Override
    protected boolean isRefreshTokenSupported(List<String> theScopes) {
        return theScopes.contains(OAuthConstants.REFRESH_TOKEN_SCOPE);
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

    public void setTokenConverter(SamlTokenConverter tokenConverter) {
        this.tokenConverter = tokenConverter;
    }

    public void setScopes(Map<String, String> scopes) {
        for (Map.Entry<String, String> entry : scopes.entrySet()) {
            OAuthPermission permission = new OAuthPermission(entry.getKey(), entry.getValue());
            if (OidcUtils.OPENID_SCOPE.equals(entry.getKey())) {
                permission.setDefault(true);
            }
            permissionMap.put(entry.getKey(), permission);
        }
    }
}
