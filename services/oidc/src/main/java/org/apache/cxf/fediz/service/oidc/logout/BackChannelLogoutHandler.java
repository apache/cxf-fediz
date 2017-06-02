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

import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.ws.rs.core.Form;

import org.apache.cxf.common.util.Base64UrlUtility;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.rs.security.jose.jwt.JoseJwtProducer;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.ServerAccessToken;
import org.apache.cxf.rs.security.oauth2.provider.OAuthDataProvider;
import org.apache.cxf.rs.security.oidc.common.IdToken;
import org.apache.cxf.rs.security.oidc.idp.OidcUserSubject;
import org.apache.cxf.rt.security.crypto.CryptoUtils;

public class BackChannelLogoutHandler extends JoseJwtProducer {
    private static final String BACK_CHANNEL_LOGOUT_URI = "backchannel_logout_uri";
    private static final String LOGOUT_TOKEN = "logout_token";
    private static final String EVENTS_PROPERTY = "events";
    private static final String BACK_CHANNEL_LOGOUT_EVENT =
        "http://schemas.openid.net/event/backchannel-logout";
    private ExecutorService executorService = Executors.newCachedThreadPool();
    private OAuthDataProvider dataProvider;
        
    public void handleLogout(Client client, OidcUserSubject subject, IdToken idTokenHint) {
        // At the moment the only to find out which RPs a given User is logged in is
        // to check the access tokens - it can not offer a complete solution, for ex
        // in cases when ATs have expired or been revoked or Implicit id_token flow is used.
        // Most likely a 'visited sites' cookie as suggested by the spec will need to be used.
        List<ServerAccessToken> accessTokens = dataProvider.getAccessTokens(client,  subject);
        for (ServerAccessToken at : accessTokens) {
            if (client.getClientId().equals(at.getClient().getClientId())) {
                continue;
            }
            String uri = client.getProperties().get(BACK_CHANNEL_LOGOUT_URI);
            if (uri != null) {
                submitBackChannelLogoutRequest(client, subject, idTokenHint, uri);
            }
        }

    }

    private void submitBackChannelLogoutRequest(Client client, OidcUserSubject subject,
            IdToken idTokenHint, String uri) {
        // Application context is expected to contain HttpConduit HTTPS configuration
        final WebClient wc = WebClient.create(uri);
        IdToken idToken = idTokenHint != null ? idTokenHint : subject.getIdToken(); 
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(idToken.getIssuer());
        claims.setSubject(idToken.getSubject());
        claims.setAudience(client.getClientId());
        claims.setIssuedAt(System.currentTimeMillis() / 1000);
        claims.setTokenId(Base64UrlUtility.encode(CryptoUtils.generateSecureRandomBytes(16)));
        claims.setProperty(EVENTS_PROPERTY, 
                Collections.singletonMap(BACK_CHANNEL_LOGOUT_EVENT, Collections.emptyMap()));
        final String logoutToken = super.processJwt(new JwtToken(claims));
        executorService.submit(new Runnable() {

            @Override
            public void run() {
                wc.form(new Form().param(LOGOUT_TOKEN, logoutToken));
            }
        
        });
        
    }

    public void setDataProvider(OAuthDataProvider dataProvider) {
        this.dataProvider = dataProvider;
    }
    
    public void close() {
        executorService.shutdownNow();
    }
}
