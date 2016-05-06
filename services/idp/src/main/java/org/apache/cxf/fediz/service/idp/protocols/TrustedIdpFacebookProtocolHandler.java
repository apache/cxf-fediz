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

package org.apache.cxf.fediz.service.idp.protocols;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.core.Form;
import javax.ws.rs.core.Response;

import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.domain.TrustedIdp;
import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.apache.cxf.interceptor.LoggingInInterceptor;
import org.apache.cxf.interceptor.LoggingOutInterceptor;
import org.apache.cxf.jaxrs.client.ClientConfiguration;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.jaxrs.json.basic.JsonMapObject;
import org.apache.cxf.jaxrs.provider.json.JsonMapObjectProvider;
import org.apache.cxf.rs.security.oauth2.common.ClientAccessToken;
import org.apache.cxf.rs.security.oauth2.provider.OAuthJSONProvider;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.RequestContext;

/**
 * Extension of AbstractTrustedIdpOAuth2ProtocolHandler for Facebook Connect.
 * Default values:
 *  - scope: email
 *  - token.endpoint: https://graph.facebook.com/v2.6/oauth/access_token
 */
@Component
public class TrustedIdpFacebookProtocolHandler extends AbstractTrustedIdpOAuth2ProtocolHandler {
    
    /**
     * The facebook API endpoint for querying claims (such as email address). If not specified
     * it defaults to "https://graph.facebook.com/v2.6".
     */
    public static final String API_ENDPOINT = "api.endpoint";
    
    /**
     * The Claim to use for the subject username to insert into the SAML Token. It defaults to 
     * "email".
     */
    public static final String SUBJECT_CLAIM = "subject.claim";
    
    public static final String PROTOCOL = "facebook-connect";

    private static final Logger LOG = LoggerFactory.getLogger(TrustedIdpFacebookProtocolHandler.class);

    @Override
    public String getProtocol() {
        return PROTOCOL;
    }

    @Override
    public SecurityToken mapSignInResponse(RequestContext context, Idp idp, TrustedIdp trustedIdp) {

        String code = (String) WebUtils.getAttributeFromFlowScope(context,
                                                                  OAuthConstants.CODE_RESPONSE_TYPE);
        if (code != null && !code.isEmpty()) {
            
            String tokenEndpoint = getProperty(trustedIdp, TOKEN_ENDPOINT);
            if (tokenEndpoint == null || tokenEndpoint.isEmpty()) {
                tokenEndpoint = "https://graph.facebook.com/v2.6/oauth/access_token";
            }
            
            String apiEndpoint = getProperty(trustedIdp, API_ENDPOINT);
            if (apiEndpoint == null || apiEndpoint.isEmpty()) {
                apiEndpoint = "https://graph.facebook.com/v2.6";
            }
            
            String clientId = getProperty(trustedIdp, CLIENT_ID);
            String clientSecret = getProperty(trustedIdp, CLIENT_SECRET);
            if (clientSecret == null || clientSecret.isEmpty()) {
                LOG.warn("A CLIENT_SECRET must be configured to use the TrustedIdpFacebookProtocolHandler");
                throw new IllegalStateException("No CLIENT_SECRET specified");
            }
            
            // Here we need to get the AccessToken using the authorization code
            List<Object> providers = new ArrayList<Object>();
            providers.add(new OAuthJSONProvider());
            
            WebClient client = 
                WebClient.create(tokenEndpoint, providers, "cxf-tls.xml");
            
            ClientConfiguration config = WebClient.getConfig(client);

            if (LOG.isDebugEnabled()) {
                config.getOutInterceptors().add(new LoggingOutInterceptor());
                config.getInInterceptors().add(new LoggingInInterceptor());
            }
            
            client.type("application/x-www-form-urlencoded");
            client.accept("application/json");

            Form form = new Form();
            form.param("grant_type", "authorization_code");
            form.param("code", code);
            form.param("client_id", clientId);
            form.param("redirect_uri", idp.getIdpUrl().toString());
            form.param("client_secret", clientSecret);
            Response response = client.post(form);

            ClientAccessToken accessToken = response.readEntity(ClientAccessToken.class);
            if (accessToken == null || accessToken.getTokenKey() == null) {
                LOG.warn("No Access Token received from the Facebook IdP");
                return null;
            }
            
            // Now we need to invoke on the API endpoint using the access token to get the 
            // user's claims
            providers.clear();
            providers.add(new JsonMapObjectProvider());
            client = WebClient.create(apiEndpoint, providers, "cxf-tls.xml");
            client.path("/me");
            config = WebClient.getConfig(client);

            if (LOG.isDebugEnabled()) {
                config.getOutInterceptors().add(new LoggingOutInterceptor());
                config.getInInterceptors().add(new LoggingInInterceptor());
            }

            client.accept("application/json");
            client.query("access_token", accessToken.getTokenKey());
            
            String subjectName = getProperty(trustedIdp, SUBJECT_CLAIM);
            if (subjectName == null || subjectName.isEmpty()) {
                subjectName = "email";
            }
            client.query("fields", subjectName);
            JsonMapObject mapObject = client.get(JsonMapObject.class);
            try {
                System.out.println("SUBJ: " + URLDecoder.decode((String)mapObject.getProperty(subjectName), "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            /*
            try {
                String whr = (String) WebUtils.getAttributeFromFlowScope(context,
                                                                         FederationConstants.PARAM_HOME_REALM);
                if (whr == null) {
                    LOG.warn("Home realm is null");
                    throw new IllegalStateException("Home realm is null");
                }
        
                // Parse the received Token
                JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(idToken);
                JwtToken jwt = jwtConsumer.getJwtToken();
                
                if (jwt != null && jwt.getClaims() != null && LOG.isDebugEnabled()) {
                    LOG.debug("Received Claims:");
                    for (Map.Entry<String, Object> claim : jwt.getClaims().asMap().entrySet()) {
                        LOG.debug(claim.getKey() + ": " + claim.getValue());
                    }
                }
                
                if (jwt != null && jwt.getJwsHeaders() != null && LOG.isDebugEnabled()) {
                    LOG.debug("Received JWS Headers:");
                    for (Map.Entry<String, Object> header : jwt.getJwsHeaders().asMap().entrySet()) {
                        LOG.debug(header.getKey() + ": " + header.getValue());
                    }
                }
                
                if (!validateSignature(trustedIdp, jwtConsumer)) {
                    LOG.warn("Signature does not validate");
                    return null;
                }
                
                // Make sure the received token is valid according to the spec
                validateToken(jwt, clientId);
                
                Date created = new Date((long)jwt.getClaim(JwtConstants.CLAIM_ISSUED_AT) * 1000L);
                Date expires = new Date((long)jwt.getClaim(JwtConstants.CLAIM_EXPIRY) * 1000L);
                
                // Convert into a SAML Token
                SamlAssertionWrapper assertion = createSamlAssertion(idp, trustedIdp, jwt, created, expires);
                Document doc = DOMUtils.createDocument();
                Element token = assertion.toDOM(doc);
        
                // Create new Security token with new id. 
                // Parameters for freshness computation are copied from original IDP_TOKEN
                SecurityToken idpToken = new SecurityToken(assertion.getId(), created, expires);
                idpToken.setToken(token);
        
                LOG.info("[IDP_TOKEN={}] for user '{}' created from [RP_TOKEN={}] issued by home realm [{}/{}]",
                         assertion.getId(), assertion.getSaml2().getSubject().getNameID().getValue(), 
                         jwt.getClaim(JwtConstants.CLAIM_JWT_ID), whr, jwt.getClaim(JwtConstants.CLAIM_ISSUER));
                LOG.debug("Created date={}", created);
                LOG.debug("Expired date={}", expires);
                
                return idpToken;
            } catch (IllegalStateException ex) {
                throw ex;
            } catch (Exception ex) {
                LOG.warn("Unexpected exception occured", ex);
                throw new IllegalStateException("Unexpected exception occured: " + ex.getMessage());
            }
            */
        }
        return null;
    }
    
    protected String getScope(TrustedIdp trustedIdp) {
        String scope = getProperty(trustedIdp, SCOPE);
        if (scope != null) {
            scope = scope.trim();
        }
        
        if (scope == null || scope.isEmpty()) {
            scope = "email";
        }
        return scope;
    }
}
