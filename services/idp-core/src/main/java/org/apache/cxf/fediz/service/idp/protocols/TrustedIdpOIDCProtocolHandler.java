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

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.Form;
import javax.ws.rs.core.Response;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.util.CertsUtils;
import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.cxf.fediz.service.idp.IdpConstants;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.domain.TrustedIdp;
import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.apache.cxf.interceptor.LoggingInInterceptor;
import org.apache.cxf.interceptor.LoggingOutInterceptor;
import org.apache.cxf.jaxrs.client.ClientConfiguration;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.rs.security.jose.common.JoseConstants;
import org.apache.cxf.rs.security.jose.jaxrs.JsonWebKeysProvider;
import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKeys;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactConsumer;
import org.apache.cxf.rs.security.jose.jwt.JwtConstants;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.apache.cxf.rs.security.jose.jwt.JwtUtils;
import org.apache.cxf.rs.security.oauth2.common.ClientAccessToken;
import org.apache.cxf.rs.security.oauth2.provider.OAuthJSONProvider;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.RequestContext;

/**
 * Extension of AbstractTrustedIdpOAuth2ProtocolHandler for OpenId Connect.
 * Default values:
 *  - scope: openid
 */
@Component
public class TrustedIdpOIDCProtocolHandler extends AbstractTrustedIdpOAuth2ProtocolHandler {

    /**
     * The signature algorithm to use in verifying the IdToken. The default is "RS256".
     */
    public static final String SIGNATURE_ALGORITHM = "signature.algorithm";

    /**
     * The Claim in which to extract the Subject username to insert into the generated SAML token.
     * It defaults to "preferred_username", otherwise it falls back to the "sub" claim.
     */
    public static final String SUBJECT_CLAIM = "subject.claim";

    /**
     * Additional (space-separated) parameters to be sent in the "scope" to the authorization endpoint.
     * Fediz will automatically use "openid" for this value.
     */
    public static final String SCOPE = "scope";

    /**
     * The URI from which to retrieve the JSON Web Keys to validate the signed IdToken.
     */
    public static final String JWKS_URI = "jwks.uri";

    public static final String PROTOCOL = "openid-connect-1.0";

    private static final Logger LOG = LoggerFactory.getLogger(TrustedIdpOIDCProtocolHandler.class);

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
                LOG.warn("A TOKEN_ENDPOINT must be configured to use the OIDCProtocolHandler");
                throw new IllegalStateException("No TOKEN_ENDPOINT specified");
            }

            String clientId = getProperty(trustedIdp, CLIENT_ID);
            String clientSecret = getProperty(trustedIdp, CLIENT_SECRET);
            if (clientSecret == null || clientSecret.isEmpty()) {
                LOG.warn("A CLIENT_SECRET must be configured to use the OIDCProtocolHandler");
                throw new IllegalStateException("No CLIENT_SECRET specified");
            }

            // Here we need to get the IdToken using the authorization code
            List<Object> providers = new ArrayList<>();
            providers.add(new OAuthJSONProvider());

            WebClient client =
                WebClient.create(tokenEndpoint, providers, clientId, clientSecret, "cxf-tls.xml");

            if (LOG.isDebugEnabled()) {
                ClientConfiguration config = WebClient.getConfig(client);
                config.getOutInterceptors().add(new LoggingOutInterceptor());
                config.getInInterceptors().add(new LoggingInInterceptor());
            }

            client.type("application/x-www-form-urlencoded").accept("application/json");

            Form form = new Form();
            form.param("grant_type", "authorization_code");
            form.param("code", code);
            form.param("client_id", clientId);
            form.param("redirect_uri", idp.getIdpUrl().toString());
            Response response = client.post(form);

            ClientAccessToken accessToken = response.readEntity(ClientAccessToken.class);
            String idToken = accessToken.getParameters().get("id_token");
            if (idToken == null) {
                LOG.warn("No IdToken received from the OIDC IdP");
                return null;
            }

            client.close();

            try {
                String whr = (String) WebUtils.getAttributeFromFlowScope(context, IdpConstants.HOME_REALM);
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
                Date notBefore = null;
                if (jwt.getClaim(JwtConstants.CLAIM_NOT_BEFORE) != null) {
                    notBefore = new Date((long)jwt.getClaim(JwtConstants.CLAIM_NOT_BEFORE) * 1000L);
                }

                Date expires = new Date((long)jwt.getClaim(JwtConstants.CLAIM_EXPIRY) * 1000L);

                // Subject
                String subjectName = getProperty(trustedIdp, SUBJECT_CLAIM);
                LOG.debug("Trying to extract subject name using the claim name {}", subjectName);
                if (subjectName == null || jwt.getClaim(subjectName) == null) {
                    LOG.debug("No claim available in the token for {}", subjectName);
                    subjectName = "preferred_username";
                    LOG.debug("Falling back to use subject claim name {}", subjectName);
                    if (subjectName == null || jwt.getClaim(subjectName) == null) {
                        subjectName = JwtConstants.CLAIM_SUBJECT;
                        LOG.debug("No claim available in the token for preferred_username. "
                                  + "Falling back to use {}", subjectName);
                    }
                }

                // Convert into a SAML Token
                SamlAssertionWrapper assertion =
                    createSamlAssertion(idp, trustedIdp, jwt.getClaims(), (String)jwt.getClaim(subjectName), 
                                        notBefore, expires);
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
        }
        return null;
    }

    protected void validateToken(JwtToken jwt, String clientId) {
        // We must have the following claims
        if (jwt.getClaim(JwtConstants.CLAIM_ISSUER) == null
            || jwt.getClaim(JwtConstants.CLAIM_SUBJECT) == null
            || jwt.getClaim(JwtConstants.CLAIM_AUDIENCE) == null
            || jwt.getClaim(JwtConstants.CLAIM_EXPIRY) == null
            || jwt.getClaim(JwtConstants.CLAIM_ISSUED_AT) == null) {
            LOG.warn("The IdToken is missing a required claim");
            throw new IllegalStateException("The IdToken is missing a required claim");
        }

        // The audience must match the client_id of this client
        boolean match = false;
        for (String audience : jwt.getClaims().getAudiences()) {
            if (clientId.equals(audience)) {
                match = true;
                break;
            }
        }
        if (!match) {
            LOG.warn("The audience of the token does not match this client");
            throw new IllegalStateException("The audience of the token does not match this client");
        }

        JwtUtils.validateTokenClaims(jwt.getClaims(), 300, 0, false);
    }

    private boolean validateSignature(TrustedIdp trustedIdp, JwsJwtCompactConsumer jwtConsumer)
        throws CertificateException, WSSecurityException, Base64DecodingException,
            ProcessingException, IOException {

        // Validate the Signature
        String sigAlgo = getProperty(trustedIdp, SIGNATURE_ALGORITHM);
        if (sigAlgo == null || sigAlgo.isEmpty()) {
            sigAlgo = "RS256";
        }

        JwtToken jwt = jwtConsumer.getJwtToken();
        String jwksUri = getProperty(trustedIdp, JWKS_URI);
        JsonWebKey verifyingKey = null;

        if (jwksUri != null && jwt.getJwsHeaders() != null
            && jwt.getJwsHeaders().containsHeader(JoseConstants.HEADER_KEY_ID)) {
            String kid = (String)jwt.getJwsHeaders().getHeader(JoseConstants.HEADER_KEY_ID);
            LOG.debug("Attemping to retrieve key id {} from uri {}", kid, jwksUri);
            List<Object> jsonKeyProviders = new ArrayList<>();
            jsonKeyProviders.add(new JsonWebKeysProvider());

            WebClient client =
                WebClient.create(jwksUri, jsonKeyProviders, "cxf-tls.xml");
            client.accept("application/json");

            ClientConfiguration config = WebClient.getConfig(client);
            if (LOG.isDebugEnabled()) {
                config.getOutInterceptors().add(new LoggingOutInterceptor());
                config.getInInterceptors().add(new LoggingInInterceptor());
            }

            Response response = client.get();
            JsonWebKeys jsonWebKeys = response.readEntity(JsonWebKeys.class);
            if (jsonWebKeys != null) {
                verifyingKey = jsonWebKeys.getKey(kid);
            }
        }

        if (verifyingKey != null) {
            return jwtConsumer.verifySignatureWith(verifyingKey, SignatureAlgorithm.getAlgorithm(sigAlgo));
        }

        X509Certificate validatingCert = CertsUtils.parseX509Certificate(trustedIdp.getCertificate());
        if (validatingCert != null) {
            return jwtConsumer.verifySignatureWith(validatingCert, SignatureAlgorithm.getAlgorithm(sigAlgo));
        }

        LOG.warn("No key supplied to verify the signature of the IdToken");
        return false;
    }

    protected String getScope(TrustedIdp trustedIdp) {
        String scope = getProperty(trustedIdp, SCOPE);
        if (scope != null) {
            scope = scope.trim();
            if (!scope.contains("openid")) {
                scope = "openid " + scope;
            }
        }

        if (scope == null || scope.isEmpty()) {
            scope = "openid";
        }
        return scope;
    }

}
