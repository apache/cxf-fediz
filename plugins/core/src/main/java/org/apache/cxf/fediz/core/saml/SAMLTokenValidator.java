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

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import org.w3c.dom.Element;

import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimCollection;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.core.TokenValidator;
import org.apache.cxf.fediz.core.TokenValidatorResponse;
import org.apache.cxf.fediz.core.config.CertificateValidationMethod;
import org.apache.cxf.fediz.core.config.FederationContext;
import org.apache.cxf.fediz.core.config.FederationProtocol;
import org.apache.cxf.fediz.core.config.TrustManager;
import org.apache.cxf.fediz.core.config.TrustedIssuer;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.exception.ProcessingException.TYPE;
import org.apache.cxf.fediz.core.saml.SamlAssertionValidator.TRUST_TYPE;

import org.apache.ws.security.SAMLTokenPrincipal;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.validate.Credential;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class SAMLTokenValidator implements TokenValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SAMLTokenValidator.class);
    

    @Override
    public boolean canHandleTokenType(String tokenType) {
        if (WSConstants.WSS_SAML2_TOKEN_TYPE.equals(tokenType) || WSConstants.SAML2_NS.equals(tokenType)
            || WSConstants.WSS_SAML_TOKEN_TYPE.equals(tokenType) || WSConstants.SAML_NS.equals(tokenType)) {
            return true;
        }
        return false;
    }

    @Override
    public boolean canHandleToken(Element token) {
        String ns = token.getNamespaceURI();
        if (WSConstants.SAML2_NS.equals(ns) || WSConstants.SAML_NS.equals(ns)) {
            return true;
        }
        return false;
    }
    
    public TokenValidatorResponse validateAndProcessToken(Element token,
            FederationContext config) throws ProcessingException {

        try {          
            RequestData requestData = new RequestData();
            WSSConfig wssConfig = WSSConfig.getNewInstance();
            requestData.setWssConfig(wssConfig);
            // not needed as no private key must be read
            // requestData.setCallbackHandler(new
            // PasswordCallbackHandler(password));

            AssertionWrapper assertion = new AssertionWrapper(token);
            if (!assertion.isSigned()) {
                LOG.warn("Assertion is not signed");
                throw new ProcessingException(TYPE.TOKEN_NO_SIGNATURE);
            }
            // Verify the signature
            assertion.verifySignature(requestData,
                    new WSDocInfo(token.getOwnerDocument()));

            // Now verify trust on the signature
            Credential trustCredential = new Credential();
            SAMLKeyInfo samlKeyInfo = assertion.getSignatureKeyInfo();
            trustCredential.setPublicKey(samlKeyInfo.getPublicKey());
            trustCredential.setCertificates(samlKeyInfo.getCerts());
            trustCredential.setAssertion(assertion);

            SamlAssertionValidator trustValidator = new SamlAssertionValidator();
            trustValidator.setFutureTTL(config.getMaximumClockSkew().intValue());
            
            boolean trusted = false;
            String assertionIssuer = assertion.getIssuerString();
            
            List<TrustedIssuer> trustedIssuers = config.getTrustedIssuers();
            for (TrustedIssuer ti : trustedIssuers) {
                List<String> subjectConstraints = Collections.singletonList(ti.getSubject());
                if (ti.getCertificateValidationMethod().equals(CertificateValidationMethod.CHAIN_TRUST)) {
                    trustValidator.setSubjectConstraints(subjectConstraints);
                    trustValidator.setSignatureTrustType(TRUST_TYPE.CHAIN_TRUST_CONSTRAINTS);
                } else if (ti.getCertificateValidationMethod().equals(CertificateValidationMethod.PEER_TRUST)) {
                    trustValidator.setSignatureTrustType(TRUST_TYPE.PEER_TRUST);
                } else {
                    throw new IllegalStateException("Unsupported certificate validation method: " 
                                                    + ti.getCertificateValidationMethod());
                }
                try {
                    for (TrustManager tm: config.getCertificateStores()) {
                        try {
                            requestData.setSigCrypto(tm.getCrypto());
                            trustValidator.validate(trustCredential, requestData);
                            trusted = true;
                            break;
                        } catch (Exception ex) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Issuer '" + ti.getName() + "' not validated in keystore '"
                                          + tm.getName() + "'");
                            }
                        }
                    }
                    if (trusted) {
                        break;
                    }
                    
                } catch (Exception ex) {
                    if (LOG.isInfoEnabled()) {
                        LOG.info("Issuer '" + assertionIssuer + "' doesn't match trusted issuer '" + ti.getName()
                                 + "': " + ex.getMessage());
                    }
                }
            }
            
            if (!trusted) {
                // Condition already checked in SamlAssertionValidator
                // Minor performance impact on untrusted and expired tokens
                if (!isConditionValid(assertion, config.getMaximumClockSkew().intValue())) {
                    LOG.warn("Security token expired");
                    throw new ProcessingException(TYPE.TOKEN_EXPIRED);
                } else {
                    LOG.warn("Issuer '" + assertionIssuer + "' not trusted");
                    throw new ProcessingException(TYPE.ISSUER_NOT_TRUSTED);
                }
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
            if (fp.getRoleURI() != null) {
                URI roleURI = URI.create(fp.getRoleURI());
                String delim = fp.getRoleDelimiter();
                for (Claim c : claims) {
                    if (roleURI.equals(c.getClaimType())) {
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
                            LOG.error("Unsupported value type of Claim value");
                            throw new IllegalStateException("Unsupported value type of Claim value");
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
            LOG.error("Security token validation failed", ex);
            throw new ProcessingException(TYPE.TOKEN_INVALID);
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
                if (attribute.getAttributeNamespace() != null) {
                    URI attrName = URI.create(attribute.getAttributeName());
                    if (attrName.isAbsolute()) {
                        // Workaround for CXF-4484
                        c.setClaimType(attrName);
                        if (attribute.getAttributeName().startsWith(attribute.getAttributeNamespace())) {
                            LOG.info("AttributeName fully qualified '" + attribute.getAttributeName()
                                     + "' but does match with AttributeNamespace '"
                                     + attribute.getAttributeNamespace() + "'");
                        } else {
                            LOG.warn("AttributeName fully qualified '" + attribute.getAttributeName()
                                     + "' but does NOT match with AttributeNamespace (ignored) '"
                                     + attribute.getAttributeNamespace() + "'");
                        }
                    } else {
                        if (attribute.getAttributeNamespace().endsWith("/")) {
                            c.setClaimType(URI.create(attribute.getAttributeNamespace()
                                                      + attribute.getAttributeName()));
                        } else {
                            c.setClaimType(URI.create(attribute.getAttributeNamespace()
                                                      + "/" + attribute.getAttributeName()));
                        }
                    }
                } else {
                    c.setClaimType(URI.create(attribute.getAttributeName()));
                }
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
                // Workaround for CXF-4484 
                // Value of Attribute Name not fully qualified
                // if NameFormat is http://schemas.xmlsoap.org/ws/2005/05/identity/claims
                // but ClaimType value must be fully qualified as Namespace attribute goes away
                URI attrName = URI.create(attribute.getName());
                if (ClaimTypes.URI_BASE.toString().equals(attribute.getNameFormat())
                    && !attrName.isAbsolute()) {
                    c.setClaimType(URI.create(ClaimTypes.URI_BASE + "/" + attribute.getName()));
                } else {
                    c.setClaimType(URI.create(attribute.getName()));
                }
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
                t.setValue(values);
            } else if (oValue instanceof List<?>) {
                //more than one child element AttributeValue
                List<String> values = (List<String>)oValue;
                values.addAll(valueList);
                t.setValue(values);
            } else {
                LOG.error("Unsupported value type of Claim value");
                throw new IllegalStateException("Unsupported value type of Claim value");
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
    
    /**
     * Check the Conditions of the Assertion.
     */
    protected boolean isConditionValid(AssertionWrapper assertion, int maxClockSkew) throws WSSecurityException {
        DateTime validFrom = null;
        DateTime validTill = null;
        if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_20)
            && assertion.getSaml2().getConditions() != null) {
            validFrom = assertion.getSaml2().getConditions().getNotBefore();
            validTill = assertion.getSaml2().getConditions().getNotOnOrAfter();
        } else if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_11)
            && assertion.getSaml1().getConditions() != null) {
            validFrom = assertion.getSaml1().getConditions().getNotBefore();
            validTill = assertion.getSaml1().getConditions().getNotOnOrAfter();
        }
        
        if (validFrom != null) {
            DateTime currentTime = new DateTime();
            currentTime = currentTime.plusSeconds(maxClockSkew);
            if (validFrom.isAfter(currentTime)) {
                LOG.debug("SAML Token condition (Not Before) not met");
                return false;
            }
        }

        if (validTill != null && validTill.isBeforeNow()) {
            LOG.debug("SAML Token condition (Not On Or After) not met");
            return false;
        }
        return true;
    }
    

}
