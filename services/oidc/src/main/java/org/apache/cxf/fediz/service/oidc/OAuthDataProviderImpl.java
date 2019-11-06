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

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.ServerAccessToken;
import org.apache.cxf.rs.security.oauth2.grants.code.JCacheCodeDataProvider;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.tokens.refresh.RefreshToken;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.apache.cxf.rs.security.oauth2.utils.OAuthUtils;
import org.apache.cxf.rs.security.oidc.utils.OidcUtils;

public class OAuthDataProviderImpl extends JCacheCodeDataProvider {
    private static final Set<String> NON_REDIRECTION_FLOWS = 
        new HashSet<>(Arrays.asList(OAuthConstants.CLIENT_CREDENTIALS_GRANT, 
                                    OAuthConstants.RESOURCE_OWNER_GRANT));

    @Override
    protected void checkRequestedScopes(Client client, List<String> requestedScopes) {
        String grantType = super.getCurrentRequestedGrantType();
        if (grantType != null && !NON_REDIRECTION_FLOWS.contains(grantType)    
            && !requestedScopes.contains(OidcUtils.OPENID_SCOPE)) {
            throw new OAuthServiceException("Required scopes are missing");
        }
    }

    //
    // BEGIN - TODO This can be removed once we pick up CXF 3.3.5
    //

    @Override
    public ServerAccessToken refreshAccessToken(Client client, String refreshTokenKey,
                                                List<String> restrictedScopes) throws OAuthServiceException {
        RefreshToken currentRefreshToken = isRecycleRefreshTokens()
            ? revokeRefreshToken(client, refreshTokenKey) : getRefreshToken(refreshTokenKey);
        if (currentRefreshToken == null) {
            throw new OAuthServiceException(OAuthConstants.ACCESS_DENIED);
        }
        if (OAuthUtils.isExpired(currentRefreshToken.getIssuedAt(), currentRefreshToken.getExpiresIn())) {
            if (!isRecycleRefreshTokens()) {
                revokeRefreshToken(client, refreshTokenKey);
            }
            throw new OAuthServiceException(OAuthConstants.ACCESS_DENIED);
        }
        if (isRecycleRefreshTokens()) {
            revokeAccessTokens(client, currentRefreshToken);
        }

        ServerAccessToken at = doRefreshAccessToken(client, currentRefreshToken, restrictedScopes);
        saveAccessToken(at);
        if (isRecycleRefreshTokens()) {
            createNewRefreshToken(at);
        } else {
            updateExistingRefreshToken(currentRefreshToken, at);
        }
        return at;
    }

    @Override
    public void revokeToken(Client client, String tokenKey, String tokenTypeHint) throws OAuthServiceException {
        ServerAccessToken accessToken = null;
        if (!OAuthConstants.REFRESH_TOKEN.equals(tokenTypeHint)) {
            accessToken = revokeAccessToken(client, tokenKey);
        }
        if (accessToken != null) {
            handleLinkedRefreshToken(client, accessToken);
        } else if (!OAuthConstants.ACCESS_TOKEN.equals(tokenTypeHint)) {
            RefreshToken currentRefreshToken = revokeRefreshToken(client, tokenKey);
            revokeAccessTokens(client, currentRefreshToken);
        }
    }

    protected void handleLinkedRefreshToken(Client client, ServerAccessToken accessToken) {
        if (accessToken != null && accessToken.getRefreshToken() != null) {
            RefreshToken rt = getRefreshToken(accessToken.getRefreshToken());
            if (rt == null) {
                return;
            }

            unlinkRefreshAccessToken(rt, accessToken.getTokenKey());
            if (rt.getAccessTokens().isEmpty()) {
                revokeRefreshToken(client, rt.getTokenKey());
            } else {
                saveRefreshToken(rt);
            }
        }

    }

    protected void revokeAccessTokens(Client client, RefreshToken currentRefreshToken) {
        if (currentRefreshToken != null) {
            for (String accessTokenKey : currentRefreshToken.getAccessTokens()) {
                revokeAccessToken(client, accessTokenKey);
            }
        }
    }

    protected ServerAccessToken revokeAccessToken(Client client, String accessTokenKey) {
        ServerAccessToken at = getAccessToken(accessTokenKey);
        if (at != null) {
            if (!at.getClient().getClientId().equals(client.getClientId())) {
                throw new OAuthServiceException(OAuthConstants.INVALID_GRANT);
            }
            doRevokeAccessToken(at);
        }
        return at;
    }

    protected RefreshToken revokeRefreshToken(Client client, String refreshTokenKey) {
        RefreshToken refreshToken = getRefreshToken(refreshTokenKey);
        if (refreshToken != null) {
            if (!refreshToken.getClient().getClientId().equals(client.getClientId())) {
                throw new OAuthServiceException(OAuthConstants.INVALID_GRANT);
            }
            doRevokeRefreshToken(refreshToken);
        }
        return refreshToken;
    }

    //
    // END
    //
}
