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
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.Response;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.util.CertsUtils;
import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.cxf.fediz.service.idp.IdpConstants;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.domain.TrustedIdp;
import org.apache.cxf.fediz.service.idp.spi.TrustedIdpProtocolHandler;
import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.apache.cxf.interceptor.LoggingInInterceptor;
import org.apache.cxf.interceptor.LoggingOutInterceptor;
import org.apache.cxf.jaxrs.client.ClientConfiguration;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactConsumer;
import org.apache.cxf.rs.security.jose.jwt.JwtConstants;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.apache.cxf.rs.security.jose.jwt.JwtUtils;
import org.apache.cxf.rs.security.oauth2.common.ClientAccessToken;
import org.apache.cxf.rs.security.oauth2.provider.OAuthJSONProvider;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.wss4j.common.crypto.CertificateStore;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.ConditionsBean;
import org.apache.wss4j.common.saml.bean.SubjectBean;
import org.apache.wss4j.common.saml.bean.Version;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.RequestContext;

@Component
public class TrustedIdpOIDCProtocolHandler implements TrustedIdpProtocolHandler {
    
    /**
     * The client_id value to send to the OIDC IdP.
     */
    public static final String CLIENT_ID = "client.id";
    
    /**
     * The secret associated with the client to authenticate to the OIDC IdP.
     */
    public static final String CLIENT_SECRET = "client.secret";
    
    /**
     * The Token endpoint. The authorization endpoint is specified by TrustedIdp.url.
     */
    public static final String TOKEN_ENDPOINT = "token.endpoint";
    
    /**
     * The signature algorithm to use in verifying the IdToken. The default is "RS256".
     */
    public static final String SIGNATURE_ALGORITHM = "signature.algorithm";
    
    /**
     * The Claim in which to extract the Subject username to insert into the generated SAML token. 
     * It defaults to "preferred_username", otherwise it falls back to the "sub" claim.
     */
    public static final String SUBJECT_CLAIM = "subject.claim";
    
    public static final String PROTOCOL = "openid-connect-1.0";

    private static final Logger LOG = LoggerFactory.getLogger(TrustedIdpOIDCProtocolHandler.class);

    @Override
    public boolean canHandleRequest(HttpServletRequest request) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public String getProtocol() {
        return PROTOCOL;
    }

    @Override
    public URL mapSignInRequest(RequestContext context, Idp idp, TrustedIdp trustedIdp) {
        
        String clientId = getProperty(trustedIdp, CLIENT_ID);
        if (clientId == null || clientId.isEmpty()) {
            LOG.warn("A CLIENT_ID must be configured to use the OIDCProtocolHandler");
            throw new IllegalStateException("No CLIENT_ID specified");
        }
        
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(trustedIdp.getUrl());
            sb.append("?");
            sb.append("response_type").append('=');
            sb.append("code");
            sb.append("&");
            sb.append("client_id").append('=');
            sb.append(clientId);
            sb.append("&");
            sb.append("redirect_uri").append('=');
            sb.append(URLEncoder.encode(idp.getIdpUrl().toString(), "UTF-8"));
            sb.append("&");
            sb.append("scope").append('=');
            sb.append("openid");
            
            String state = context.getFlowScope().getString(IdpConstants.TRUSTED_IDP_CONTEXT);
            sb.append("&").append("state").append('=');
            sb.append(state);
            
            return new URL(sb.toString());
        } catch (MalformedURLException ex) {
            LOG.error("Invalid Redirect URL for Trusted Idp", ex);
            throw new IllegalStateException("Invalid Redirect URL for Trusted Idp");
        } catch (UnsupportedEncodingException ex) {
            LOG.error("Invalid Redirect URL for Trusted Idp", ex);
            throw new IllegalStateException("Invalid Redirect URL for Trusted Idp");
        }
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
            List<Object> providers = new ArrayList<Object>();
            providers.add(new OAuthJSONProvider());
            
            WebClient client = 
                WebClient.create(tokenEndpoint, providers, clientId, clientSecret, null);
            
            ClientConfiguration config = WebClient.getConfig(client);

            if (LOG.isDebugEnabled()) {
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
            
            try {
                X509Certificate validatingCert = getCertificate(trustedIdp.getCertificate());
                if (validatingCert == null) {
                    LOG.warn("No X.509 Certificate configured for signature validation");
                    return null;
                }
                
                String whr = (String) WebUtils.getAttributeFromFlowScope(context,
                                                                         FederationConstants.PARAM_HOME_REALM);
                if (whr == null) {
                    LOG.warn("Home realm is null");
                    throw new IllegalStateException("Home realm is null");
                }
        
                // Parse the received Token
                JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(idToken);
                JwtToken jwt = jwtConsumer.getJwtToken();
                
                // Validate the Signature
                String sigAlgo = getProperty(trustedIdp, SIGNATURE_ALGORITHM);
                if (sigAlgo == null || sigAlgo.isEmpty()) {
                    sigAlgo = "RS256";
                }
                if (!jwtConsumer.verifySignatureWith(validatingCert, SignatureAlgorithm.getAlgorithm(sigAlgo))) {
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
    
    private Crypto getCrypto(String certificate) throws ProcessingException {
        if (certificate == null) {
            return null;
        }
        
        boolean isCertificateLocation = !certificate.startsWith("-----BEGIN CERTIFICATE");
        if (isCertificateLocation) {
            try {
                X509Certificate cert = CertsUtils.getX509Certificate(certificate);
                if (cert == null) {
                    return null;
                }
                return new CertificateStore(new X509Certificate[]{cert});
            } catch (CertificateException ex) {
                // Maybe it's a WSS4J properties file...
                return CertsUtils.createCrypto(certificate);
            }
        } 
        
        // Here the certificate is encoded in the configuration file
        X509Certificate cert;
        try {
            cert = CertsUtils.parseCertificate(certificate);
        } catch (Exception ex) {
            LOG.error("Failed to parse trusted certificate", ex);
            throw new ProcessingException("Failed to parse trusted certificate");
        }
        return new CertificateStore(Collections.singletonList(cert).toArray(new X509Certificate[0]));
    }
    
    private X509Certificate getCertificate(String certificate) 
        throws CertificateException, WSSecurityException, ProcessingException, Base64DecodingException, IOException {
        if (certificate == null) {
            return null;
        }
        
        boolean isCertificateLocation = !certificate.startsWith("-----BEGIN CERTIFICATE");
        if (isCertificateLocation) {
            try {
                return CertsUtils.getX509Certificate(certificate);
            } catch (CertificateException ex) {
                // Maybe it's a WSS4J properties file...
                Crypto crypto = CertsUtils.createCrypto(certificate);
                if (crypto != null) {
                    return CertsUtils.getX509Certificate(crypto, null);
                }
            }
        } 
        
        // Here the certificate is encoded in the configuration file
        try {
            return CertsUtils.parseCertificate(certificate);
        } catch (Exception ex) {
            LOG.error("Failed to parse trusted certificate", ex);
            throw new ProcessingException("Failed to parse trusted certificate");
        }
    }
    
    protected SamlAssertionWrapper createSamlAssertion(Idp idp, TrustedIdp trustedIdp, JwtToken token,
                                                     Date created,
                                                     Date expires) throws Exception {
        SamlCallbackHandler callbackHandler = new SamlCallbackHandler();
        String issuer = idp.getServiceDisplayName();
        if (issuer == null) {
            issuer = idp.getRealm();
        }
        if (issuer != null) {
            callbackHandler.setIssuer(issuer);
        }
        
        // Subject
        String subjectName = getProperty(trustedIdp, SUBJECT_CLAIM);
        if (subjectName == null || token.getClaim(subjectName) == null) {
            subjectName = "preferred_username";
            if (subjectName == null || token.getClaim(subjectName) == null) {
                subjectName = JwtConstants.CLAIM_SUBJECT;
            }
        }
        
        SubjectBean subjectBean =
            new SubjectBean((String)token.getClaim(subjectName), 
                            SAML2Constants.NAMEID_FORMAT_UNSPECIFIED, 
                            SAML2Constants.CONF_BEARER);
        callbackHandler.setSubjectBean(subjectBean);
        
        // Conditions
        ConditionsBean conditionsBean = new ConditionsBean();
        conditionsBean.setNotAfter(new DateTime(expires));
        if (token.getClaim(JwtConstants.CLAIM_NOT_BEFORE) != null) {
            DateTime notBefore = new DateTime((long)token.getClaim(JwtConstants.CLAIM_NOT_BEFORE) * 1000L);
            conditionsBean.setNotBefore(notBefore);
        } else {
            conditionsBean.setNotBefore(new DateTime());
        }
        callbackHandler.setConditionsBean(conditionsBean);
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);
        
        Crypto crypto = getCrypto(idp.getCertificate());
        assertion.signAssertion(crypto.getDefaultX509Identifier(), idp.getCertificatePassword(), 
                                crypto, false);
        
        return assertion;
    }
    
    private String getProperty(TrustedIdp trustedIdp, String property) {
        Map<String, String> parameters = trustedIdp.getParameters();
        
        if (parameters != null && parameters.containsKey(property)) {
            return parameters.get(property);
        }
        
        return null;
    }
    
    private static class SamlCallbackHandler implements CallbackHandler {
        private ConditionsBean conditionsBean;
        private SubjectBean subjectBean;
        private String issuer;
        
        /**
         * Set the SubjectBean
         */
        public void setSubjectBean(SubjectBean subjectBean) {
            this.subjectBean = subjectBean;
        }
        
        /**
         * Set the ConditionsBean
         */
        public void setConditionsBean(ConditionsBean conditionsBean) {
            this.conditionsBean = conditionsBean;
        }
        
        /**
         * Set the issuer name
         */
        public void setIssuer(String issuerName) {
            this.issuer = issuerName;
        }
        
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof SAMLCallback) {
                    SAMLCallback samlCallback = (SAMLCallback) callback;

                    // Set the Subject
                    if (subjectBean != null) {
                        samlCallback.setSubject(subjectBean);
                    }
                    samlCallback.setSamlVersion(Version.SAML_20);
                    
                    // Set the issuer
                    samlCallback.setIssuer(issuer);

                    // Set the conditions
                    samlCallback.setConditions(conditionsBean);
                }
            }
        }
        
    }

}
