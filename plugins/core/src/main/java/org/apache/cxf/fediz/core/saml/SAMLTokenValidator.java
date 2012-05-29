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

package org.apache.cxf.fediz.core.saml;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.StringTokenizer;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.w3c.dom.Element;

import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimCollection;
import org.apache.cxf.fediz.core.TokenValidator;
import org.apache.cxf.fediz.core.TokenValidatorResponse;
import org.apache.cxf.fediz.core.config.FederationContext;
import org.apache.cxf.fediz.core.config.FederationProtocol;
import org.apache.cxf.fediz.core.config.KeyStore;
import org.apache.cxf.fediz.core.config.TrustManager;
import org.apache.cxf.fediz.core.config.TrustedIssuer;

import org.apache.ws.security.SAMLTokenPrincipal;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.validate.Credential;
import org.apache.ws.security.validate.SignatureTrustValidator;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.ValidatorSuite;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class SAMLTokenValidator implements TokenValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SAMLTokenValidator.class);
    
    // [TODO] make sure we answer true only for cases we actually can handle
    @Override
    public boolean canHandleTokenType(String tokenType) {
        return true;
    }

    @Override
    public boolean canHandleToken(Element token) {
        return true;
    }
    
    public TokenValidatorResponse validateAndProcessToken(Element token,
            FederationContext config) {

        try {
            String trustStoreFile;
            String trustStorePw;
            //[TODO] Support more than one truststore
            TrustManager tm = config.getCertificateStores().get(0);
            KeyStore ks = tm.getKeyStore();
            if (ks.getFile() != null && !ks.getFile().isEmpty()) {
                trustStoreFile = ks.getFile();
                trustStorePw = ks.getPassword();
            } else {
                throw new IllegalStateException("No certificate store configured");
            }
            
            File f = new File(trustStoreFile);
            if (!f.exists() && config.getRelativePath() != null && !config.getRelativePath().isEmpty()) {
                trustStoreFile = config.getRelativePath().concat(File.separator + trustStoreFile);
            }
            
            Properties sigProperties = createCryptoProviderProperties(trustStoreFile, trustStorePw);

            Crypto sigCrypto = CryptoFactory.getInstance(sigProperties);
            RequestData requestData = new RequestData();
            requestData.setSigCrypto(sigCrypto);
            WSSConfig wssConfig = WSSConfig.getNewInstance();
            requestData.setWssConfig(wssConfig);
            // not needed as no private key must be read
            // requestData.setCallbackHandler(new
            // PasswordCallbackHandler(password));

            AssertionWrapper assertion = new AssertionWrapper(token);
            if (!assertion.isSigned()) {
                throw new RuntimeException(
                        "The received assertion is not signed, and therefore not trusted");
            }
            // Verify the signature
            assertion.verifySignature(requestData,
                    new WSDocInfo(token.getOwnerDocument()));
            
            // Validate the assertion against schemas/profiles
            validateAssertion(assertion);
            
            // Validate Conditions
            if (config.isDetectExpiredTokens() && !validateConditions(assertion, config)) {
                throw new RuntimeException(
                    "Error in validating conditions of the received Assertion"
                );
            }

            // Now verify trust on the signature
            Credential trustCredential = new Credential();
            SAMLKeyInfo samlKeyInfo = assertion.getSignatureKeyInfo();
            trustCredential.setPublicKey(samlKeyInfo.getPublicKey());
            trustCredential.setCertificates(samlKeyInfo.getCerts());

            SignatureTrustValidator trustValidator = new SignatureTrustValidator();
            trustValidator.validate(trustCredential, requestData);

            String assertionIssuer = assertion.getIssuerString();

            // Finally check that subject DN of the signing certificate matches
            // a known constraint
            X509Certificate cert = null;
            if (trustCredential.getCertificates() != null) {
                cert = trustCredential.getCertificates()[0];
            }

            // [TODO] Support more than one trusted issuer
            List<TrustedIssuer> trustedIssuers = config.getTrustedIssuers();
            TrustedIssuer ti = trustedIssuers.get(0);
            List<String> subjectConstraints = Collections.singletonList(ti.getSubject());

            CertConstraintsParser certConstraints = new CertConstraintsParser();
            certConstraints.setSubjectConstraints(subjectConstraints);

            if (!certConstraints.matches(cert)) {
                throw new RuntimeException("Issuer '" + assertionIssuer
                        + "' not trusted");
            }

            String audience = null;
            List<Claim> claims = null;
            if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_20)) {
                claims = parseClaimsInAssertion(assertion.getSaml2());
                audience = getAudienceRestriction(assertion.getSaml2());
            } else if (assertion.getSamlVersion()
                    .equals(SAMLVersion.VERSION_11)) {
                claims = parseClaimsInAssertion(assertion.getSaml1());
                audience = getAudienceRestriction(assertion.getSaml1());
            }

            List<String> roles = null;
            FederationProtocol fp = (FederationProtocol)config.getProtocol();
            URI roleURI = URI.create(fp.getRoleURI());
            String delim = fp.getRoleDelimiter();
            if (roleURI != null) {
                for (Claim c : claims) {
                    URI claimURI = URI.create(c.getNamespace() + "/"
                            + c.getClaimType());
                    if (roleURI.equals(claimURI)) {
                        Object oValue = c.getValue();
                        if (oValue instanceof String) {
                            if (delim == null) {
                                roles = Collections.singletonList((String)oValue);
                            } else {
                                roles = parseRoles((String)oValue, delim);
                            }
                        } else if (oValue instanceof List<?>) {
                            List<String> values = (List<String>)oValue;
                            roles = Collections.unmodifiableList(values);
                        } else {
                            throw new IllegalStateException("Invalid value type of Claim value");
                        }
                        claims.remove(c);
                        break;
                    }
                }
            }

            SAMLTokenPrincipal p = new SAMLTokenPrincipal(assertion);

            TokenValidatorResponse response = new TokenValidatorResponse(
                    assertion.getId(), p.getName(), assertionIssuer, roles,
                    new ClaimCollection(claims), audience);
            response.setExpires(getExpires(assertion));
            
            return response;

        } catch (WSSecurityException ex) {
            // [TODO] proper exception handling
            throw new RuntimeException(ex);
        }
    }

    protected List<Claim> parseClaimsInAssertion(
            org.opensaml.saml1.core.Assertion assertion) {
        List<org.opensaml.saml1.core.AttributeStatement> attributeStatements = assertion
                .getAttributeStatements();
        if (attributeStatements == null || attributeStatements.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No attribute statements found");
            }
            return Collections.emptyList();
        }
        List<Claim> collection = new ArrayList<Claim>();
        Map<String, Claim> claimsMap = new HashMap<String, Claim>();

        for (org.opensaml.saml1.core.AttributeStatement statement : attributeStatements) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("parsing statement: " + statement.getElementQName());
            }

            List<org.opensaml.saml1.core.Attribute> attributes = statement
                    .getAttributes();
            for (org.opensaml.saml1.core.Attribute attribute : attributes) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("parsing attribute: "
                            + attribute.getAttributeName());
                }
                Claim c = new Claim();
                c.setIssuer(assertion.getIssuer());
                c.setClaimType(URI.create(attribute.getAttributeName()));
                List<String> valueList = new ArrayList<String>();
                for (XMLObject attributeValue : attribute.getAttributeValues()) {
                    Element attributeValueElement = attributeValue.getDOM();
                    String value = attributeValueElement.getTextContent();
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(" [" + value + "]");
                    }
                    valueList.add(value);
                }
                mergeClaimToMap(claimsMap, c, valueList);
            }
        }
        collection.addAll(claimsMap.values());
        return collection;
    }



    protected List<Claim> parseClaimsInAssertion(
            org.opensaml.saml2.core.Assertion assertion) {
        List<org.opensaml.saml2.core.AttributeStatement> attributeStatements = assertion
                .getAttributeStatements();
        if (attributeStatements == null || attributeStatements.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No attribute statements found");
            }
            return Collections.emptyList();
        }

        List<Claim> collection = new ArrayList<Claim>();
        Map<String, Claim> claimsMap = new HashMap<String, Claim>();

        for (org.opensaml.saml2.core.AttributeStatement statement : attributeStatements) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("parsing statement: " + statement.getElementQName());
            }
            List<org.opensaml.saml2.core.Attribute> attributes = statement
                    .getAttributes();
            for (org.opensaml.saml2.core.Attribute attribute : attributes) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("parsing attribute: " + attribute.getName());
                }
                Claim c = new Claim();
                c.setClaimType(URI.create(attribute.getName()));
                c.setIssuer(assertion.getIssuer().getNameQualifier());
                
                List<String> valueList = new ArrayList<String>();
                for (XMLObject attributeValue : attribute.getAttributeValues()) {
                    Element attributeValueElement = attributeValue.getDOM();
                    String value = attributeValueElement.getTextContent();
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(" [" + value + "]");
                    }
                    valueList.add(value);
                }
                mergeClaimToMap(claimsMap, c, valueList);
            }
        }
        collection.addAll(claimsMap.values());
        return collection;

    }

    protected void mergeClaimToMap(Map<String, Claim> claimsMap, Claim c,
            List<String> valueList) {
        Claim t = claimsMap.get(c.getClaimType().toString());
        if (t != null) {
            //same SAML attribute already processed. Thus Claim object already created.
            Object oValue = t.getValue();
            if (oValue instanceof String) {
                //one child element AttributeValue only
                List<String> values = new ArrayList<String>();
                values.add((String)oValue); //add existing value
                values.addAll(valueList);
            } else if (oValue instanceof List<?>) {
                //more than one child element AttributeValue
                List<String> values = (List<String>)oValue;
                values.addAll(valueList);
            } else {
                throw new IllegalStateException("Invalid value type of Claim value");
            }
        } else {
            if (valueList.size() == 1) {
                c.setValue(valueList.get(0));
            } else {
                c.setValue(valueList);
            }
            // Add claim to map
            claimsMap.put(c.getClaimType().toString(), c);
        }
    }
    
    protected List<String> parseRoles(String value, String delim) {
        List<String> roles = new ArrayList<String>();
        StringTokenizer st = new StringTokenizer(value, delim);
        while (st.hasMoreTokens()) {
            String role = st.nextToken();
            roles.add(role);
        }
        return roles;
    }

    protected String getAudienceRestriction(
            org.opensaml.saml1.core.Assertion assertion) {
        String audience = null;
        try {
            audience = assertion.getConditions()
                    .getAudienceRestrictionConditions().get(0).getAudiences()
                    .get(0).getUri();
        } catch (Exception ex) {
            LOG.warn("Failed to read audience" + ex.getMessage());
        }
        return audience;
    }

    protected String getAudienceRestriction(
            org.opensaml.saml2.core.Assertion assertion) {
        String audience = null;
        try {
            audience = assertion.getConditions().getAudienceRestrictions()
                    .get(0).getAudiences().get(0).getAudienceURI();
        } catch (Exception ex) {
            LOG.warn("Failed to read audience" + ex.getMessage());
        }
        return audience;

    }

    protected Properties createCryptoProviderProperties(String truststoreFile,
            String truststorePassword) {
        Properties p = new Properties();
        p.put("org.apache.ws.security.crypto.provider",
                "org.apache.ws.security.components.crypto.Merlin");
        p.put("org.apache.ws.security.crypto.merlin.keystore.type", "jks");
        p.put("org.apache.ws.security.crypto.merlin.keystore.password",
                truststorePassword);
        p.put("org.apache.ws.security.crypto.merlin.keystore.file",
                truststoreFile);
        return p;
    }
    
    /**
     * Validate the assertion against schemas/profiles
     */
    protected void validateAssertion(AssertionWrapper assertion) throws WSSecurityException {
        if (assertion.getSaml1() != null) {
            ValidatorSuite schemaValidators = 
                org.opensaml.Configuration.getValidatorSuite("saml1-schema-validator");
            ValidatorSuite specValidators = 
                org.opensaml.Configuration.getValidatorSuite("saml1-spec-validator");
            try {
                schemaValidators.validate(assertion.getSaml1());
                specValidators.validate(assertion.getSaml1());
            } catch (ValidationException e) {
                LOG.debug("Saml Validation error: " + e.getMessage());
                throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity");
            }
        } else if (assertion.getSaml2() != null) {
            ValidatorSuite schemaValidators = 
                org.opensaml.Configuration.getValidatorSuite("saml2-core-schema-validator");
            ValidatorSuite specValidators = 
                org.opensaml.Configuration.getValidatorSuite("saml2-core-spec-validator");
            try {
                schemaValidators.validate(assertion.getSaml2());
                specValidators.validate(assertion.getSaml2());
            } catch (ValidationException e) {
                LOG.debug("Saml Validation error: " + e.getMessage());
                throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity");
            }
        }
    }
    
    protected boolean validateConditions(
        AssertionWrapper assertion,
        FederationContext config
    ) {
        DateTime validFrom = null;
        DateTime validTill = null;
        if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_20)) {
            validFrom = assertion.getSaml2().getConditions().getNotBefore();
            validTill = assertion.getSaml2().getConditions().getNotOnOrAfter();
        } else {
            validFrom = assertion.getSaml1().getConditions().getNotBefore();
            validTill = assertion.getSaml1().getConditions().getNotOnOrAfter();
        }
        
        if (validFrom != null) {
            DateTime currentTime = new DateTime();
            currentTime = currentTime.plusSeconds(config.getMaximumClockSkew().intValue());
            if (validFrom.isAfter(currentTime)) {
                LOG.warn("SAML Token condition (Not Before) not met");
                return false;
            }
        }
        
        if (validTill != null && validTill.isBeforeNow()) {
            LOG.debug("SAML Token condition (Not On Or After) not met");
            return false;
        }
        
        return true;
    }
    
    private Date getExpires(AssertionWrapper assertion) {
        DateTime validTill = null;
        if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_20)) {
            validTill = assertion.getSaml2().getConditions().getNotOnOrAfter();
        } else {
            validTill = assertion.getSaml1().getConditions().getNotOnOrAfter();
        }
        
        if (validTill == null) {
            return null;
        }
        return validTill.toDate();
    }

    // A sample MyHandler class
    class PasswordCallbackHandler implements CallbackHandler {
        private String password;

        public PasswordCallbackHandler(String password) {
            this.password = password;
        }

        public void handle(Callback[] callbacks) throws IOException,
                UnsupportedCallbackException {
            for (int i = 0; i < callbacks.length; i++) {
                if (callbacks[i] instanceof WSPasswordCallback) {
                    WSPasswordCallback nc = (WSPasswordCallback) callbacks[i];
                    nc.setPassword(this.password);
                } else {
                    throw new UnsupportedCallbackException(callbacks[i],
                            "Unrecognized Callback");
                }
            }
        }
    }
}
